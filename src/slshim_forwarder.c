/* The companion .def file supplies the DLL's complete forwarder export table. */
int __stdcall sl_forwarder_entry(void *module,unsigned reason,void *reserved)
{
    (void)module;(void)reason;(void)reserved;
    return 1;
}
