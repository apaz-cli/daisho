
# Types

These are all the different kinds of types.

```
1. CTypes
2. Typedefs
3. Classes
4. Generics
5. Traits
6. Lambda Expressions
7. Pointers
8. Arrays
```

For the most part, all of them are created equal. Methods can be attached to 
any type.


## CTypes

Stilts's concept of a primitive/integral type is replaced with ctype. Since 
Stilts transpiles to C, C types are the base of the type system. An important 
feature is that you can define your own. And also strap methods to them.

In fact, this is how the entire standard library is designed. `Int` from the 
standard library is declared with `ctype int32_t Int;`. The reason why 
`5 + 4` is valid in the language is becuause `operator+(Int rhs)` is 
implemented on `Int` as a native method. There is no such thing as 
primitive addition. Or primitive anything else. Everything traces back to 
native implementations in the standard library.

Builtin functions such as `sizeof()` work on ctypes (and every other type) 
because the compiler literally generates `sizeof(type)`. This means that any 
ctype you declare must be fully-qualified type. Otherwise the whole thing will 
almost certainly explode.


## Typedefs

A typedef is a literal stand-in for another type name. The compiler literally 
does a replacement. You just reference the type by a different name, another 
type is not actually created.


## Classes

An object is literally a C struct. So when you have an object containing 
members, you literally have a C struct containing those members. Likewise, a 
class containing another class is a struct containing another struct.

The constraint on this is that a class cannot contain an instance of itself as 
a member, or a trait it implements as a member, or any other trait where an 
implementation of that trait contains the class as a member. 

Let n be the size of an instance of the class. Let k be the total size of the 
other members. Then if an instance of the class contains itself, its size is 
`n = n + k`. You could say "okay, k is zero. The class only contains itself." 
But what use is that? Therefore, we disallow a class containing an instance 
of itself.


## Generics

Generic types are a stand-in for another type. But unlike typedefs, you can 
do a lot more with these. You can use them for polymorphism. You can add 
generics to methods, classes, and structs.

```rust
// Some classes and traits
trait Animal { String speak(); }
class Dog impl Animal {
	String speak() return "WOOF";
}
class Sheep impl Animal {
	String speak() return "BAAAA";
}

// Generic on a trait
trait AnimalBox<T> where T impl Animal

// A class using a generic trait, passing the generic through.
class Crate<T> impl AnimalBox<T> {
	T item;

	Crate();
	Crate(T item) this.item = item;

	T getItem() return this.item;
	Void setItem(T item) this.item = item;
}

// Generic on a Function
T unboxer(AnimalBox<T> box) {
	return box.getItem();
}


Int main() {
	// Box<Dog> inferred by its arguments
	Box<Dog> dogbox = Box<Dog>(Dog());
	Box<Sheep> sheepbox = Box<>(Sheep());
}
```


## Traits

Any type can implement a Trait. A trait is a tool to enforce that the type it's 
on implements all the required methods. It's a contract made between the 
programmer and the compiler. If you break that contract, you'll be notified 
with an error.

There are two ways to use a trait.
1. Static  (Compile-time)
2. Dynamic (Runtime)


First let's talk about option two, dynamic traits. Unlike in Rust, Stilts 
traits are real types. They do exist at runtime. An instance of a trait has 
a size, and a storage duration. You cannot instantiate a trait, but you can 
instantiate a class that implements a trait, and store it into a trait 
variable. It will behave like an instance of that trait, because it is one.

How are runtime traits implemented? A trait instance is struct containing a 
vtable and a union of all the types which implement it. The current type is 
is kept track of by the trait instance's vtable. Checking whether a trait is 
an instance of a type is the same as comparing the vtable pointers, as they 
are static. Calling a runtime trait's method is as simple as reaching into 
the vtable and pulling out the method.

Since a runtime trait is a union, its size is the largest size out of every 
type that implements it, plus the size of a pointer on your machine. The total 
overhead is the size of an extra pointer, plus the cost of accessing the vtable 
pointer, plus the cost of a virtual function call. The chances are pretty good 
that stiltc emits code for this which your C compiler will optimize. The 
clang/gcc static optimizers will probably do away with some, or perhaps even 
all of this already negligible overhead where possible. However, for those 
inclined, there exists another, zero-overhead option.

Now, it's time to talk about compile time traits. Traits are also useful at 
compile time to place constraints on generics.

There are two ways to use traits.

1. Enforce that a generic type has certain methods
```rust
trait Animal { String speak(); }
class Dog impl Animal {
	String speak() return "WOOF";
}

class Sheep impl Animal {}
impl Animal for Sheep {
	String speak() return "BAAAA";
}


Void makeSpeak(Animal animal) print(animal.speak());


Int main() {
	Dog d = Dog();
	Sheep s = Sheep();

	makeSpeak(d);
	makeSpeak(s);
}
```

At compile time, two specializations of `makeSpeak()` are created. These get 
the signatures `Void makeSpeak(Dog animal)` and `Void makeSpeak(Sheep animal)`.
They behave as you would expect.

The benefit to you, the programmer, is twofold.
1. You can use `animal.speak()` in `makeSpeak()`, even though the compiler 
doesn't know at that point exactly what method it's calling.
2. `makeSpeak()` only accepts an `Animal` as an argument, but it accepts any 
type of `Animal`. You get polymorphism, with no performance cost.

Note that the following are equivalent. Whenever you use a Trait as a type, it 
uses a generic type in disguise. There's a little bit of nuance to this.

```rust
Void makeSpeak(Animal animal)
Void <A impl Animal> makeSpeak(A animal)
```

But it uses a different generic type for each. This can come up

### TODO finish this section when I understand more.


## Lambda Expressions

The other use for Traits is for lambda expressions. Consider this drastic 
simplification of the previous example.
```rust
trait Animal { String speak(); }
Void <A impl Animal> makeSpeak(A animal)

Int main() {
	/* A lambda expression with no captures or arguments */
	Animal cat = []() => { return "Meow?"};
	makeSpeak(cat);
}
```


A lambda expression is simply a singleton instance of an anonymous class, 
containing its captures as members, and implements a functional trait, which 
is stored in a runtime instance of that trait. That trait instance is what we 
call a lambda expression. That's a lot to take in at once, so allow me to 
break it down over multiple paragraphs.

What kind of type your lambda has cannot be named. It has a trait type, but 
you cannot know what implementation. You can't read it off your screen, nor can 
you type it on your keyboard. That's why we call it "anonymous." You cannot 
know its identity. And yet you have one. But since you don't know the 
implementing type's name, you can't make another one. This is why we call it a 
"singleon." However, have all we need to know. We know that it fufills its 
trait. That's why we can call the lambda expression's methods, including 
operators like the call operator, even without knowing what it actually is.

Since Animal is a Trait with only one unimplemented method, we call it a 
"functional" trait. This is the constraint that we need to declare a lambda on 
a trait. The reason is as follows. When you declare a lambda, the compiler is 
able to automatically infer what trait you're trying to implement on by 
contextual information, but the compiler does need to know what method the 
lambda's body is an implementation of. Lambdas are generally associated with 
being used as higher-order functions, hence the "functional" part, but can 
also be used as generic objects, as shown above. After all, the enlightened 
know that objects are simply a poor man's closures, and vice-versa.

If you don't know what I'm talking about, read this before continuing.
http://people.csail.mit.edu/gregs/ll1-discuss-archive-html/msg03277.html

When you declare a lambda expression, you expect it to capture variables from 
the context it was declared in. This is called a closure. This closure is 
expressed in Stilts as an object, since as master Qc Na has taught us, the two 
are equivalent. Captures are just a fancy way to provide arguments to a 
constructor. That's how we get an instance of our lambda. This closure object 
is the anonymous type that implements our functional trait.

Hopefully this clears up some confusion about how lambda expressions are 
handled.

# Pointers

C lets you choose to pass by value or reference, and do pointer arithmetic. 
Why should Stilts be less powerful than C? You can take the memory address of 
variables, and dereference them as well. No problem. Similarly, if you want 
to call `malloc()` to allocate a number of bytes, that's totally allowed. 
The standard library provides it, along with `sizeof()`. If you want to, you 
can do memory management in Stilts exactly the same way as in C. Just 
`malloc()` and `free()` your way to victory.

One difference is that Stilts is much kinder with implicit conversions. 
Suppose you have an interesting type, with a lot going on.
```rust
trait Mammal impl Printable { String getName(); }
trait Animal<T> {}
trait Person impl Animal<T> where T impl Mammal {}
trait Trickster impl Person {}
class George impl Trickster { String getName() return "George"; }
class Herold impl Trickster { String getName() return "Herold"; }

Void printMammalPtr(Mammal* m) println(m.getName());
Void printMammalStack(Mammal m) println(m.getName());

Int main() {
	Mammal george = George();
	Trickster* herold = new Herold();

	// Calling conventions are equivalent
	printMammalStack(george);
	printMammalStack(herold);
	printMammalPtr(george);
	printMammalPtr(herold);

	del(herold);
}
```

The following happens behind the scenes, in order:
 * Space for the variables `george` and `herold` are set aside on the stack. 
   Since `herold` has a pointer type, its size is the size of a native pointer 
   on your machine. The size of `George` depends on what other types implement 
   Mammal.
 * The default constructor for `George` is called, creating an instance of 
   `George` on the stack.
 * This `George` instance is stored into the `george` variable, which is of 
   type `Mammal`. An implicit conversion is performed. This has a small 
   overhead, since a runtime trait type contains a vtable, a pointer to which 
   must be stored with our `George` and also be initialized before `main()`.
   be initialized before main().
 * A `new` `Herold` is created on the heap. It is not guaranteed that this 
   object instance is allocated by `malloc()`, so don't try to `free()` it. 
   Clean it up with `del` instead. Immediately after space is carved out for 
   the object by Stilts's builtin allocator, `Herold`'s default constructor is 
   called on it, to initialize that memory with its contents. Constructor 
   calling conventions are exactly the same whether you allocate on the stack 
   or on the heap. The only difference is allocation overhead, required 
   cleanup, and storage duration. 
* Our `Herold` instance is converted to a trait reference type, specifically 
  `Trickster*`. The reference to our `Herold` is stored into a structure with 
  the appropriate vtable pointer. This struct is actually stored on the stack 
  and is always passed by reference. See calling conventions at the end of 
  this document for more information.



# Arrays



# Calling Conventions

## Calling methods

Whenever is a method is called on a type, it is implicitly passed a pointer of 
that type as the argument's first method. That's how the `this` pointer is 
handled.

Take, for example, the following.
```rust
class Dog {
	String sound;
	Dog() { this.sound = "Bark"; }
	void bark(Dog d) { println(this.sound); }
}

Int main() { Dog().bark(); }
```

The above generates code equivalent to:

```rust
class Dog {
	String sound;
	Dog() { this.sound = "Bark"; }
}

void bark(Dog* thisPtr, UInt times)
	for (UInt i = 0; i < times; i++)
		println(thisPtr.sound);

Int main() {
	Dog d = Dog();
	bark(&d);
}
```

## Passing arguments

Other arguments are passed the same way you would expect 
them to be passed in C. With one exception, which I'll get 
to in a moment. In general though, if you pass a value type, 
you can expect to recieve a value type.

```rust
ctype void* Fancy;
class FancyBox {
	Fancy f1; Fancy f2;
	FancyBox* fillBox(Fancy f1, Fancy* f2) {
		this.f1, this.f2 = f1, *f2;
		return this;
	}
}
```

You can expect this to generate something like:
```c
/*
 * The compiler suitably mangles the names.
 * This looks awful, but is somewhat necessary
 * to be compatible with other C code.
 *
 * If the names weren't mangled, then they could
 * end up shadowing global variables, redefinining
 * things, conflicting with your own code, creating
 * ODR violations, etc.
 *
 * In C, identifiers beginning with "__" are reserved
 * for use by the compiler. For Stilts code and C code
 * expected to work with the language, we reserve
 * "__Stilts", used anywhere within any identifiers.
 * This is enough to let us mangle names correctly.
 */

typedef void* __Stilts_Fancy;
struct __Stilts_FancyBox { __Stilts_Fancy __Stilts_f1; __Stilts_Fancy __Stilts_f2; };
typedef struct __Stilts_FancyBox __Stilts_FancyBox;

static inline __Stilts_FancyBox*
__Stilts_FancyBox_FancyBox__StiltsPtr_this_Fancy_f1_Fancy__StiltsPtr_f2_fillBox(
__Stilts_FancyBox* __Stilts_this, __Stilts_Fancy __Stilts_f1, __Stilts_Fancy* __Stilts_f2) {
	__Stilts_this->__Stilts_f1 = __Stilts_f1;
	__Stilts_this->__Stilts_f2 = __Stilts_f2;
	return __Stilts_this;
}
```

If you squint really hard, you can see that just like in the 
Stilts code that generates it, we're taking the `this` 
pointer as the first argument, a `Fancy` by value as the 
second, and a `Fancy*` (by reference) as the third. As you 
would expect.


## Automatic Conversions

Sometimes, for the sake of 
more readable code that could be readily inferred, the 
compiler will cast for you. 


## The Exception to the Rule

Now for the exception to the rule. The runtime representation 
and calling convention for trait types is slightly different. 
Suppose you have some trait with a couple classes that 
implement it.

```rust
trait Food { Void eat(UInt amount); };
trait Spicy impl Food {
	UInt getStrength();
	Void eat(UInt amount) {
		if (amount * this.getStrength() > 20)
			println("Oof oof ouch my mouth");
		else
			println("Yummy");
	};
};

class Pepper impl Spicy { UInt getStrength() return 50; }
class Yogurt impl Spicy { UInt getStrength() return 0; }

Void munchFoodValue(Food food) food.eat(2);
Void munchFoodReference(Food* food) food.eat(2);
Void munchSpicyValue(Spicy spice) spice.eat(2);
Void munchSpicyReference(Spicy* spice) spice.eat(2);

Int main() {
	// Create instances of a class on stack and heap.
	Pepper pepper = Pepper();
	Yogurt* yogurtPtr = new Yogurt();

	// You can take the memory location of a value like so:
	Pepper* pepperPtr = &pepper;

	// You can dereference a pointer like so:
	Yogurt yogurt = *yogurtPtr;

	// Assign value to value trait type.
	// There is potentially overhead here.
	Food pepperFood = pepper;
	Food yogurtFood = yogurt;

	// Assign ref to trait ref type.
	// There is still overhead here, but less
	// than from value type to trait value type.
	Food* pepperFoodPtr = pepperPtr;
	Food* yogurtFoodPtr = yogurtPtr;

	// Assign value to trait ref type.
	pepperFoodPtr = pepper;
	yogurtFoodPtr = 

	// Note you cannot 

	// Cast trait type to subtrait type

	// Try the same with pointers

}
```


