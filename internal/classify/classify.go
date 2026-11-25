// Package classify maps allocation stacks to sub-systems using ordered regex rules.
package classify

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
)

type Rule struct {
	Match     string `json:"match"`
	Subsystem string `json:"subsystem"`
	// Anywhere rules own every stack that passes through a matching frame, wherever it is (a plugin or component
	// and everything it calls); they are checked before the nearest-frame rules.
	Anywhere bool `json:"anywhere,omitempty"`
	// Module rules match unsymbolized "module+0xoffset" frames (a stripped plugin, say); name rules never see those,
	// since a file name such as ha_rocksdb.so would otherwise pass for a function name such as ha_commit_trans.
	Module bool `json:"module,omitempty"`
	// Area makes this a sub-area rule: within Subsystem, stacks it matches belong to Area ("buffer pool"). Anywhere
	// area rules are tried first, in order (the context a stack runs in: compaction, a DDL); then the frame nearest
	// the allocation that matches any non-Anywhere area rule decides. Also, when set, must match some frame too.
	Area string `json:"area,omitempty"`
	Also string `json:"also,omitempty"`
	re   *regexp.Regexp
	also *regexp.Regexp
}

// moduleFrame is how an unsymbolized frame is printed: module file name, "+0x", offset.
var moduleFrame = regexp.MustCompile(`^[^ ;]+\+0x[0-9a-f]+$`)

type Classifier struct {
	skip  *regexp.Regexp
	rules []Rule
	areas map[string][]Rule // sub-area rules by sub-system
}

// Sep joins a sub-system and its sub-area: "InnoDB · buffer pool".
const Sep = " · "

const defaultSkip = `^(malloc|calloc|realloc|free|posix_memalign|aligned_alloc|memalign|mmap|munmap|_Znw|_Zna|_Zdl|_Zda|operator new|operator delete|my_malloc|my_realloc|my_free|my_memdup|my_strdup|__libc_|\[unknown|\[anon mmap\]|\[fault)`

var defaultRules = []Rule{
	{Match: `^(audit_log_filter::|audit_log_)`, Subsystem: "AuditLog", Anywhere: true},
	{Match: `^(Json_|json_|rapidjson::|Item_func_json|parse_json|wrapper_to_)`, Subsystem: "JSON"},
	{Match: `^(ib::|buf_|btr_|fil_|log_|lock_|trx_|row_|dict_|srv_|os_mem|ut::|mem_heap|fts_|page_|fsp_|rec_|que_|pars_|ha_innobase|ha_innopart|Innodb|innobase)`, Subsystem: "InnoDB"},
	{Match: `(?i)temptable`, Subsystem: "TempTable"},
	// MyRocks (MariaDB, Percona Server): the RocksDB library and its handler, ahead of SQL's handler:: and ha_ rules.
	{Match: `^(rocksdb::|myrocks::|rocksdb_)`, Subsystem: "RocksDB"},
	{Match: `^ha_rocksdb\.so\+`, Subsystem: "RocksDB", Module: true}, // MariaDB and Percona ship the plugin stripped
	// MariaDB: Aria (system and internal temporary tables; aria_pagecache_buffer_size), MyISAM key cache
	// (key_buffer_size), MEMORY/HEAP tables (also in-memory internal temporary tables), query cache, Galera.
	{Match: `^(ha_maria|maria_|_ma_|translog_|init_pagecache|pagecache_|resize_pagecache|end_pagecache)`, Subsystem: "Aria"},
	{Match: `^(ha_myisam|mi_|myisam|myrg_|ha_myisammrg|init_key_cache|resize_key_cache|ha_init_key_cache|ha_resize_key_cache|process_key_caches|init_simple_key_cache|key_cache_|simple_key_cache)`, Subsystem: "MyISAM"},
	{Match: `^(ha_heap|heap_|hp_)`, Subsystem: "MEMORY"},
	{Match: `^(Query_cache|query_cache_)`, Subsystem: "QueryCache"},
	{Match: `(?i)^(wsrep|galera|gu::|gcomm|gcs_|gcache)`, Subsystem: "Galera"},
	{Match: `(?i)(binlog|gtid|relay|rpl_|replica|slave|applier|Replication)`, Subsystem: "Replication"},
	{Match: `(?i)(openssl|ssl_|^SSL|CRYPTO_|EVP_|ossl_)`, Subsystem: "TLS"},
	{Match: `(?i)(^PFS|pfs_|^PSI_)`, Subsystem: "PerformanceSchema"},
	{Match: `^(Item|JOIN|THD|Query_|Table_cache|Filesort|filesort|MEM_ROOT|handle_|dispatch_command|mysql_|sql_|Sql_|Opt|QEP|ha_|handler::|TABLE|open_)`, Subsystem: "SQL"},
	{Match: `^(Protocol|net_|Vio|vio_|Connection_handler|Channel_info)`, Subsystem: "Network"},
}

// defaultAreas split the storage engines into what a DBA tunes or recognizes: caches, write buffers, background work.
var defaultAreas = []Rule{
	// InnoDB: context first (the stack runs inside it), then the nearest recognizable frame.
	{Subsystem: "InnoDB", Area: "adaptive hash index", Match: `^btr_search_`, Anywhere: true},
	{Subsystem: "InnoDB", Area: "buffer pool", Match: `^(buf_pool_t::allocate_chunk|buf_chunk_init|buf_pool_create|buf_pool_init|buf_pool_resize|buf_pool_t::create|buf_pool_t::resize|buf_resize_thread)`, Anywhere: true},
	{Subsystem: "InnoDB", Area: "doublewrite pages loaded at startup", Match: `^(dblwr::recv::|Double_write::load)`, Anywhere: true},
	{Subsystem: "InnoDB", Area: "crash recovery", Match: `^recv_`, Anywhere: true},
	{Subsystem: "InnoDB", Area: "DDL & index builds", Match: `^(ddl::|row_merge_|row_log_|ha_innobase::(inplace_alter_table|prepare_inplace_alter_table|commit_inplace_alter_table)|innobase_create_index|Alter_stage)`, Anywhere: true},
	{Subsystem: "InnoDB", Area: "full-text search", Match: `^(fts_|fts::|ha_innobase::ft_)`, Anywhere: true},
	{Subsystem: "InnoDB", Area: "purge", Match: `^(trx_purge|srv_purge|srv_do_purge|row_purge|purge_sys|purge_coordinator|purge_worker)`, Anywhere: true},
	{Subsystem: "InnoDB", Area: "change buffer", Match: `^ibuf_`, Anywhere: true},
	{Subsystem: "InnoDB", Area: "MVCC old row versions", Match: `^row_vers_`},
	{Subsystem: "InnoDB", Area: "lock system", Match: `^(lock_|Locks_hashtable|RecLock|Lock_iter)`},
	{Subsystem: "InnoDB", Area: "redo log", Match: `^(log_|Log_|redo_|mtr_|mtr_t::)`},
	{Subsystem: "InnoDB", Area: "doublewrite buffer", Match: `^(dblwr::|Double_write|buf_dblwr)`},
	{Subsystem: "InnoDB", Area: "undo", Match: `^(trx_undo|trx_rseg|undo::|trx_roll|row_undo)`},
	{Subsystem: "InnoDB", Area: "transactions & read views", Match: `^(trx_|Trx_|ReadView|MVCC::)`},
	{Subsystem: "InnoDB", Area: "data dictionary cache", Match: `^(dict_|dd_|Dict_|innobase_.*dict)`},
	{Subsystem: "InnoDB", Area: "row reads", Match: `^(row_sel|row_search|Row_sel|row_prebuilt|row_create_prebuilt|ha_innobase::(index_|rnd_|general_fetch|records|position))`},
	{Subsystem: "InnoDB", Area: "row writes", Match: `^(row_ins|row_upd|row_del|row_insert|ins_node|upd_node|ha_innobase::(write_row|update_row|delete_row))`},
	{Subsystem: "InnoDB", Area: "tablespaces & file I/O", Match: `^(fil_|fsp_|Fil_|Tablespace|os_file|os_aio|AIO|Datafile)`},
	{Subsystem: "InnoDB", Area: "threads & latches", Match: `^(srv_|os_event|sync_|rw_lock|ib_mutex|Mutex)`},
	{Subsystem: "InnoDB", Area: "B-tree operations", Match: `^(btr_|page_|rec_|Btree)`},

	// RocksDB (MyRocks): background jobs by context; foreground by the nearest frame.
	{Subsystem: "RocksDB", Area: "compaction output", Anywhere: true,
		Match: `^rocksdb::(CompactionJob|CompactionIterator|MergeHelper|SubcompactionState|CompactionOutputs|DBImpl::BackgroundCompaction|DBImpl::BGWorkCompaction|CompactionPicker|Compaction::)`,
		Also:  `^rocksdb::(BlockBasedTableBuilder|BlockBuilder|.*IndexBuilder|.*FilterBlockBuilder|.*FilterBitsBuilder|CompactionOutputs::AddToOutput|SubcompactionState::AddToOutput|TableBuilder)`},
	{Subsystem: "RocksDB", Area: "compaction input", Anywhere: true,
		Match: `^rocksdb::(CompactionJob|CompactionIterator|MergeHelper|SubcompactionState|CompactionOutputs|DBImpl::BackgroundCompaction|DBImpl::BGWorkCompaction|CompactionPicker|Compaction::)`},
	{Subsystem: "RocksDB", Area: "memtable flush", Match: `^rocksdb::(FlushJob|DBImpl::BackgroundFlush|DBImpl::BGWorkFlush|BuildTable)`, Anywhere: true},
	{Subsystem: "RocksDB", Area: "index & filter blocks", Match: `^rocksdb::(.*IndexBuilder|.*FilterBlockBuilder|.*FilterBitsBuilder|.*FilterBlockReader|PartitionedIndexFilterReader|PartitionIndexReader|.*IndexReader|BloomFilterPolicy|.*FilterPolicy)`},
	{Subsystem: "RocksDB", Area: "block cache & block reads", Match: `^rocksdb::(LRUCache|ClockCache|HyperClockCache|.*CacheShard|ShardedCache|Cache::|CacheAllocation|BlockFetcher|BlockBasedTable::(RetrieveBlock|MaybeReadBlockAndLoadToCache|PutDataBlockToCache|GetDataBlockFromCache)|UncompressBlock|UncompressData|UncompressSerializedBlock|BlockContents|CachableEntry)`},
	{Subsystem: "RocksDB", Area: "WAL & info log", Match: `^rocksdb::(LogBuffer|EnvLogger|PosixLogger|WritableFileWriter|log::Writer|DBImpl::WriteToWAL|DBImpl::WriteGroupToWAL)`},
	{Subsystem: "RocksDB", Area: "memtables & write batches", Match: `^rocksdb::(MemTable::Add|MemTable::MemTable|MemTableInserter|WriteBatch|WriteBatchInternal|WriteBatchWithIndex|DBImpl::Write|DBImpl::SwitchMemtable|DBImpl::FlushMemTable|ConcurrentArena|Arena::|InlineSkipList|SkipList|WriteBufferManager|MemTableList|.*MemTableRep)`},
	{Subsystem: "RocksDB", Area: "transactions, snapshots & locks", Match: `^rocksdb::(TransactionBaseImpl|PessimisticTransaction|WritePrepared|WriteUnprepared|.*TransactionDB|TransactionUtil|SnapshotList|DBImpl::GetSnapshot|.*LockManager|PointLock|RangeLock|LockMap)`},
	{Subsystem: "RocksDB", Area: "reads & iterators", Match: `^rocksdb::(DBImpl::Get|DBImpl::MultiGet|DBImpl::NewIterator|DBIter|ArenaWrappedDBIter|MergingIterator|.*Iterator::|SaveValue|GetContext|Version::Get|TableCache::(Get|NewIterator|MultiGet)|BlockBasedTable::(Get|NewIterator|MultiGet)|.*\(anonymous namespace\)::SkipListRep::Get)`},
	{Subsystem: "RocksDB", Area: "MyRocks row encoding", Match: `^myrocks::(Rdb_converter|Rdb_key_def::pack|Rdb_string_writer|Rdb_value_field_iterator)`},
	{Subsystem: "RocksDB", Area: "MyRocks transactions", Match: `^myrocks::(Rdb_transaction|Rdb_tx|Rdb_writebatch)`},
	{Subsystem: "RocksDB", Area: "MyRocks scans", Match: `^myrocks::(Rdb_iterator|ha_rocksdb::(index_|rnd_|read_|setup_|position|get_row_by_rowid|secondary_index_read|check_and_lock|.*scan))`},
	{Subsystem: "RocksDB", Area: "MyRocks handler", Match: `^myrocks::`},
}

// New builds a classifier; rulesFile may be "" for the built-in MySQL rules.
// A rules file is a JSON array of {"match": regex, "subsystem": name} replacing the defaults.
func New(rulesFile string) (*Classifier, error) {
	rules := append(append([]Rule(nil), defaultRules...), defaultAreas...)
	if rulesFile != "" {
		b, err := os.ReadFile(rulesFile)
		if err != nil {
			return nil, err
		}
		rules = nil
		if err := json.Unmarshal(b, &rules); err != nil {
			return nil, fmt.Errorf("%s: %w", rulesFile, err)
		}
	}
	c := &Classifier{skip: regexp.MustCompile(defaultSkip), areas: map[string][]Rule{}}
	for _, r := range rules {
		re, err := regexp.Compile(r.Match)
		if err != nil {
			return nil, fmt.Errorf("rule %q: %w", r.Match, err)
		}
		r.re = re
		if r.Also != "" {
			if r.also, err = regexp.Compile(r.Also); err != nil {
				return nil, fmt.Errorf("rule %q: %w", r.Also, err)
			}
		}
		if r.Area != "" {
			c.areas[r.Subsystem] = append(c.areas[r.Subsystem], r)
			continue
		}
		c.rules = append(c.rules, r)
	}
	return c, nil
}

// Subsystem returns the area of the first Anywhere rule matching any frame; otherwise it scans the root-first stack
// from the leaf up, skipping allocator wrapper frames, and the first frame matching a rule decides. Unsymbolized
// "module+0xoffset" frames are matched by Module rules only.
func (c *Classifier) Subsystem(stack []string) string {
	for _, r := range c.rules {
		if r.Anywhere {
			for _, f := range stack {
				if r.re.MatchString(f) {
					return r.Subsystem
				}
			}
		}
	}
	for i := len(stack) - 1; i >= 0; i-- {
		f := stack[i]
		if c.skip.MatchString(f) {
			continue
		}
		mod := moduleFrame.MatchString(f)
		for _, r := range c.rules {
			if !r.Anywhere && r.Module == mod && r.re.MatchString(f) {
				return r.Subsystem
			}
		}
	}
	return "other"
}

// Area names the sub-area of a stack within its sub-system: "" when the sub-system has no area rules, "other" when
// none matched. Context (Anywhere) rules first, in order; then the frame nearest the allocation that any other rule
// of the sub-system matches.
func (c *Classifier) Area(stack []string, subsys string) string {
	rules := c.areas[subsys]
	if len(rules) == 0 {
		return ""
	}
	any := func(re *regexp.Regexp) bool {
		for _, f := range stack {
			if re.MatchString(f) {
				return true
			}
		}
		return false
	}
	for _, r := range rules {
		if r.Anywhere && any(r.re) && (r.also == nil || any(r.also)) {
			return r.Area
		}
	}
	for i := len(stack) - 1; i >= 0; i-- {
		f := stack[i]
		if c.skip.MatchString(f) {
			continue
		}
		for _, r := range rules {
			if !r.Anywhere && r.re.MatchString(f) && (r.also == nil || any(r.also)) {
				return r.Area
			}
		}
	}
	return "other"
}

// Full is the sub-system with its sub-area, if it has one: "InnoDB · buffer pool", or "SQL".
func (c *Classifier) Full(stack []string, subsys string) string {
	if a := c.Area(stack, subsys); a != "" {
		return subsys + Sep + a
	}
	return subsys
}
