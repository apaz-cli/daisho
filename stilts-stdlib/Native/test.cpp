#include <iostream>

typedef struct Type { int a; double b; } Type;

void Type__fn(Type* this, Type* other) {
  std::cout << this->a << std::endl;
}

int main() {
  Type a, b;
  Type__fn(&a, &b);
  return 0;
}
