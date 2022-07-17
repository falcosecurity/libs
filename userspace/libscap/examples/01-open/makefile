
FALCO_LIBS_DIR = "../../../.."

scap_open: scap_open.o
	gcc scap_open.o -L"${FALCO_LIBS_DIR}/build/libscap" -L"${FALCO_LIBS_DIR}/build/libscap/engine/source_plugin" -L"${FALCO_LIBS_DIR}/build/libscap/engine/noop" -L"${FALCO_LIBS_DIR}/build/libscap/engine/nodriver" -L"${FALCO_LIBS_DIR}/build/libscap/engine/bpf" -L"${FALCO_LIBS_DIR}/build/libscap/engine/kmod" -L"${FALCO_LIBS_DIR}/build/libscap/engine/udig" -L"${FALCO_LIBS_DIR}/build/libscap/engine/gvisor" -Wl,-Bstatic -lscap -lscap_engine_udig -lscap_engine_bpf -lscap_engine_kmod -lscap_event_schema -lscap_engine_util -lscap_engine_gvisor -lscap_engine_source_plugin -lscap_engine_noop -lscap_engine_nodriver -Wl,-Bdynamic -lrt -o scap_open

scap_open.o: scap_open.c
	gcc -c scap_open.c -I "../../../common" -I "../../"

clean:
	rm scap_open.o scap_open
