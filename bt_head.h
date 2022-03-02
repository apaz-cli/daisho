
void print_trace(void);

void indir2(void) {
  print_trace();
}

void indir1(void) {
  indir2();
}
