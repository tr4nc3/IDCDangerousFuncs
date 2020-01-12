#include <idc.idc>
static chop( str) {
  auto len ;
  len = strlen(str);
  return substr(str,0,len-1);
}
static main() {
  auto fd, i, funcname, badfuncaddr, source, xref, addr, funcstr; 
  Message("BOFFinder : Finding xrefs to dangerous function calls\n");
  fd = fopen("dangerous_funcs.txt","r");
  if (fd == 0) {
    Message("Error occurred in opening dangerous_funcs.txt\n");
	return;
  }
  while ( (funcstr = readstr(fd) ) != -1 ) {
    funcname = chop(funcstr);
    badfuncaddr = LocByName(funcname);
	if (badfuncaddr != BADADDR) {
	  i = 0;
	  for (addr = RfirstB(badfuncaddr); addr != BADADDR; addr = RnextB(badfuncaddr, addr) ) {
	    xref = XrefType();
		if (xref == fl_CN || xref == fl_CF) {
		  source = GetFunctionName(addr);
		  Message("%s is called from 0x%x in %s\n", funcname, addr, source);
		  i = i + 1;
		}
	  }
	  Message("--- %s called %d times ---\n",funcname,i);
	}
	/*else {
	  Message("bad address for \"%s\"\n",funcname);
	}*/
  }
  Message("**** Script execution ended ****\n");
  fclose(fd);  
}