package classify

import (
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
)

func TestSubsystem(t *testing.T) {
	c, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]string{
		"InnoDB": {"start_thread", "dispatch_command", "row_ins", "mem_heap_create_block", "my_malloc", "malloc"},
		"SQL":    {"start_thread", "dispatch_command", "Item_func::val_str", "my_malloc"},
		"TLS":    {"start_thread", "SSL_read", "CRYPTO_malloc", "malloc"},
		"other":  {"start_thread", "foo"},
		"AuditLog": {"start_thread", "dispatch_command", "mysql_audit_notify", "audit_log_filter::AuditLogFilter::notify_event",
			"audit_log_filter::log_record_formatter::LogRecordFormatter::apply", "Json_dom::parse", "std::string::reserve", "malloc"},
		"JSON": {"start_thread", "dispatch_command", "Item_func_json_insert::val_json", "Json_array::append_alias", "operator new"},
	}
	for want, st := range cases {
		if got := c.Subsystem(st); got != want {
			t.Errorf("%v: got %s want %s", st, got, want)
		}
	}
}

// Stacks recorded from MariaDB 11.4, 11.8 and 12.3.
func TestSubsystemMariaDB(t *testing.T) {
	c, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	start := []string{"_start", "mysqld_main", "init_server_components"}
	plugin := append(start, "plugin_init", "plugin_initialize", "plugin_do_initialize", "ha_initialize_handlerton")
	conn := []string{"start_thread", "pfs_spawn_thread", "handle_one_connection", "do_handle_one_connection", "do_command",
		"dispatch_command", "mysqld_stmt_execute", "mysql_execute_command", "execute_sqlcom_select", "mysql_select", "JOIN::exec_inner", "sub_select"}
	for _, c2 := range []struct {
		want  string
		stack []string
	}{
		{"InnoDB", append(plugin, "innodb_init", "srv_start", "buf_pool_t::create", "my_virtual_mem_commit")},
		{"InnoDB", append(plugin, "innodb_init", "srv_start", "recv_sys_t::find_checkpoint", "log_t::attach", "my_large_malloc")},
		{"Aria", append(plugin, "ha_maria_init", "init_pagecache", "my_large_malloc")},
		{"Aria", append(plugin, "ha_maria_init", "init_pagecache", "my_multi_malloc_large")},
		{"MyISAM", append(start, "process_key_caches", "ha_init_key_cache", "init_key_cache", "init_key_cache_internal", "init_simple_key_cache", "my_large_malloc")},
		{"MEMORY", append(conn, "evaluate_join_record", "end_write", "handler::ha_write_tmp_row", "ha_heap::write_row", "heap_write", "hp_get_new_block", "my_malloc")},
		{"SQL", append(conn, "join_init_read_record", "st_join_table::sort_table", "create_sort_index", "filesort", "Filesort_buffer::alloc_sort_buffer", "my_malloc")},
		{"SQL", []string{"start_thread", "pfs_spawn_thread", "handle_one_connection", "do_handle_one_connection", "CONNECT::create_thd"}},
		// MyRocks, MariaDB 11.6.2: INSERT ... SELECT into a RocksDB table, and a scan
		{"RocksDB", append(conn, "evaluate_join_record", "end_send", "select_insert::send_data", "write_record", "handler::ha_write_row",
			"myrocks::ha_rocksdb::write_row", "myrocks::ha_rocksdb::update_write_row", "myrocks::Rdb_transaction_impl::put",
			"rocksdb::TransactionBaseImpl::Put", "rocksdb::WriteBatchWithIndex::Put", "rocksdb::WriteBatch::Put",
			"rocksdb::WriteBatchInternal::Put", "std::string::append", "std::string::reserve", "std::string::_Rep::_M_clone", "operator new")},
		{"RocksDB", append(conn, "rr_sequential", "handler::ha_rnd_next", "myrocks::ha_rocksdb::rnd_next",
			"rocksdb::DBIter::Next", "rocksdb::BlockBasedTableIterator::InitDataBlock", "rocksdb::BlockFetcher::ReadBlockContents", "malloc")},
		{"RocksDB", append(conn, "trans_rollback_stmt", "ha_rollback_trans", "myrocks::rocksdb_rollback",
			"myrocks::Rdb_transaction_impl::rollback_stmt", "rocksdb::TransactionLockMgr::UnLock", "std::vector::_M_emplace_back_aux", "operator new")},
		{"RocksDB", []string{"__clone3", "start_thread", "rocksdb::ThreadPoolImpl::Impl::BGThread", "rocksdb::DBImpl::BackgroundCallFlush", "malloc"}},
		// Percona Server 8.4 ships ha_rocksdb.so stripped: a block-cache read ends in module+offset frames, which must
		// not pass for SQL's ha_ functions; the nearest named frame (rocksdb::) decides
		{"RocksDB", []string{"__clone3", "start_thread", "mysqld+0x123d9b5", "do_command", "dispatch_command", "mysql_execute_command",
			"handler::ha_index_next", "myrocks::ha_rocksdb::index_next_with_direction_intern", "rocksdb::DBIter::Next",
			"rocksdb::DBIter::FindNextUserEntryInternal", "ha_rocksdb.so+0x661f06", "ha_rocksdb.so+0x6247b9", "operator new"}},
		// only stripped plugin frames: the module rule
		{"RocksDB", []string{"__clone3", "start_thread", "libstdc++.so.6.0.33+0xecdb3", "ha_rocksdb.so+0x656357", "ha_rocksdb.so+0x6247b9", "malloc"}},
		// an unknown stripped plugin is not SQL either
		{"other", []string{"__clone3", "start_thread", "ha_example.so+0x1234", "malloc"}},
		{"Galera", []string{"start_thread", "wsrep_replication_process", "wsrep::wsrep_provider_v26::run_applier", "galera::ReplicatorSMM::async_recv", "malloc"}},
	} {
		if got := c.Subsystem(c2.stack); got != c2.want {
			t.Errorf("%v: got %s want %s", c2.stack, got, c2.want)
		}
	}
}

// TestAreasFolded prints the sub-area breakdown of a real folded-stacks file (MHP_FOLDED=path; root-first frames
// joined by ";", then the bytes), with the largest stacks left in "other" per sub-system.
func TestAreasFolded(t *testing.T) {
	path := os.Getenv("MHP_FOLDED")
	if path == "" {
		t.Skip("MHP_FOLDED not set")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := New("")
	by := map[string]int64{}
	type st struct {
		n int64
		s string
	}
	other := map[string][]st{}
	for _, l := range strings.Split(string(b), "\n") {
		i := strings.LastIndexByte(l, ' ')
		if i < 0 {
			continue
		}
		n, _ := strconv.ParseInt(l[i+1:], 10, 64)
		stack := strings.Split(l[:i], ";")
		sub := c.Subsystem(stack)
		full := c.Full(stack, sub)
		by[full] += n
		if strings.HasSuffix(full, Sep+"other") {
			other[sub] = append(other[sub], st{n, l[:i]})
		}
	}
	keys := make([]string, 0, len(by))
	for k := range by {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return by[keys[i]] > by[keys[j]] })
	for _, k := range keys {
		t.Logf("%10.1f MiB  %s", float64(by[k])/(1<<20), k)
	}
	for sub, l := range other {
		sort.Slice(l, func(i, j int) bool { return l[i].n > l[j].n })
		for _, x := range l[:min(len(l), 6)] {
			fr := strings.Split(x.s, ";")
			t.Logf("other in %s %8.1f MiB: %s", sub, float64(x.n)/(1<<20), strings.Join(fr[max(0, len(fr)-6):], " ; "))
		}
	}
}

// Sub-areas, from stacks recorded on Percona Server 8.4 (MyRocks) and 9.7 (InnoDB).
func TestAreas(t *testing.T) {
	c, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	conn := []string{"start_thread", "pfs_spawn_thread", "handle_connection", "do_command", "dispatch_command", "mysql_execute_command"}
	bg := []string{"start_thread", "rocksdb::ThreadPoolImpl::Impl::BGThread"}
	for _, x := range []struct {
		want  string
		stack []string
	}{
		{"InnoDB · buffer pool", []string{"start_thread", "std::thread::_State_impl::_M_run", "buf_pool_create", "buf_chunk_init", "buf_pool_t::allocate_chunk", "ut::detail::malloc"}},
		{"InnoDB · buffer pool", []string{"start_thread", "buf_pool_create", "buf_chunk_init", "rw_lock_create_unregistered_func", "os_event_create", "operator new"}},
		{"InnoDB · adaptive hash index", []string{"srv_start", "buf_pool_init", "btr_search_sys_create", "btr_search_sys_t::btr_search_sys_t", "ib_create", "hash_table_t::hash_table_t"}},
		{"InnoDB · doublewrite pages loaded at startup", []string{"srv_start", "SysTablespace::open_or_create", "dblwr::recv::load", "Double_write::load", "dblwr::recv::Pages::add", "malloc"}},
		{"InnoDB · MVCC old row versions", append(conn, "ha_innobase::general_fetch", "row_search_mvcc", "Row_sel_get_clust_rec_for_mysql::operator()", "row_vers_build_for_consistent_read", "mem_heap_create_block", "malloc")},
		{"InnoDB · row reads", append(conn, "ha_innobase::general_fetch", "row_search_mvcc", "mem_heap_create_block", "malloc")},
		{"InnoDB · DDL & index builds", append(conn, "ha_innobase::inplace_alter_table", "ddl::Context::build", "ddl::Builder::init", "ddl::Key_sort_buffer::Key_sort_buffer", "ut::detail::malloc")},
		{"InnoDB · other", append(conn, "ha_innobase::build_template", "mem_heap_create_block", "malloc")},
		{"RocksDB · block cache & block reads", append(conn, "myrocks::ha_rocksdb::index_next", "rocksdb::BlockBasedTable::MaybeReadBlockAndLoadToCache", "rocksdb::UncompressSerializedBlock", "rocksdb::UncompressData", "malloc")},
		{"RocksDB · MyRocks row encoding", append(conn, "myrocks::ha_rocksdb::update_write_pk", "myrocks::Rdb_converter::encode_value_slice", "String::append", "String::mem_realloc", "my_raw_malloc")},
		{"RocksDB · reads & iterators", append(conn, "rocksdb::DBImpl::GetImpl", "rocksdb::MemTable::Get", "rocksdb::(anonymous namespace)::SkipListRep::Get", "rocksdb::SaveValue", "std::__cxx11::basic_string::_M_mutate", "operator new")},
		{"RocksDB · memtables & write batches", append(conn, "myrocks::Rdb_transaction_impl::put", "rocksdb::WriteBatchWithIndex::Put", "rocksdb::WriteBatch::Put", "std::string::append", "operator new")},
		{"RocksDB · compaction output", append(bg, "rocksdb::DBImpl::BackgroundCompaction", "rocksdb::CompactionJob::Run", "rocksdb::BlockBasedTableBuilder::Add", "rocksdb::BlockBuilder::Add", "operator new")},
		{"RocksDB · compaction input", append(bg, "rocksdb::DBImpl::BackgroundCompaction", "rocksdb::CompactionJob::Run", "rocksdb::CompactionIterator::Next", "rocksdb::BlockBasedTable::RetrieveBlock", "rocksdb::UncompressData", "malloc")},
		{"RocksDB · memtable flush", append(bg, "rocksdb::DBImpl::BackgroundFlush", "rocksdb::FlushJob::Run", "rocksdb::BuildTable", "rocksdb::BlockBasedTableBuilder::Add", "operator new")},
		{"SQL", append(conn, "Item_func::val_str", "my_malloc")},
	} {
		sub := c.Subsystem(x.stack)
		if got := c.Full(x.stack, sub); got != x.want {
			t.Errorf("%s: got %q want %q", x.stack[len(x.stack)-2], got, x.want)
		}
	}
}
