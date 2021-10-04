
# Types

There are five kinds of types.
	1. CTypes
	2. Classes
	3. Generics
	4. Lambda Expressions

All of them are created equal. Methods can be attached to any type.


## CTypes

Stilts's concept of a primitive/integral type is replaced with ctype. Since 
Stilts transpiles to C, C types are the base of the type system. An important 
feature of the language is that you can define your own integral types.

In fact, this is how the entire standard library is designed. For example, 
`Int` from the standard library is declared with `ctype int32_t Int;`. The 
reason why `5 + 4` is valid in the language is becuause `operator+(Int rhs)` 
is implemented on `Int` as a native method. There is no such thing as 
primitive addition. Or primitive anything else. Everything somehow traces back 
to native implementations in the standard library.

Builtin functions such as `sizeof()` work on ctypes (and every other type) 
because the compiler literally generates `sizeof(type)`. This means that any 
ctype you declare must be fully-qualified type. Otherwise the whole thing will 
almost certainly explode.


## Classes

Classes are literally structs. So when you have a struct of ctypes, you have 
a real C struct. A class containing another class is a struct containing 
another struct, just like you would write it yourself. More on structs 
containing other types later.


## Traits

Any type can implement a Trait. All a trait does is enforce that the type it's 
on implements all the trait's methods. It's a contract made between the 
programmer and the compiler. If you break that contract, you'll be notified 
with an error. Much like interfaces in Java.

Unlike interfaces in Java, Traits don't exist at runtime. A trait is not a 
type. You cannot declare a variable that has the type of a trait. You cannot 
instantiate a trait. A trait does not have a size. There are two things that 
traits are useful for. 

There are two ways to use traits.


1. Enforce that a generic type has certain methods
```
trait Animal { String speak(); }
class Dog impl Animal {
	String speak() {
		return "WOOF";
	}
}

class Sheep impl Animal {}
impl Animal for Sheep {
	String speak() {
		return "BAAAA";
	}
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

```
Void makeSpeak(Animal animal)
Void <A impl Animal> makeSpeak(A animal)
```

But it uses a different generic type for each. This can come up

### TODO finish this section when I understand more.


## Lambda Expressions

The other use for Traits is for lambda expressions. Consider this drastic 
simplification of the previous example.
```
trait Animal { String speak(); }
Void <A impl Animal> makeSpeak(A animal)

Int main() {
	/* A lambda expression with no captures or arguments */
	Animal cat = []() => { return "Meow?"};
	makeSpeak(cat);
}
```


A lambda expression is simply the singleton instance of an anonymous type 
implementing a functional trait. That's a lot to take in, so allow me to 
break it down.

Since Animal is a Trait with only one unimplemented method, we call it a 
"functional" trait. That is to say, you can use the trait to create a lambda 
expression. Lambdas are generally associated with and used as functions, not 
with generic objects. However, this example is meant to illustrate that the 
two concepts are one and the same.

A lambda's type cannot be named. You can't read it off your screen, nor can 
you type it on your keyboard. That's why we call it "anonymous." You cannot 
know its identity. However, we do know that it fufills its trait. So, we can 
call the lambda expression's methods, including operators like the call 
operator.

The lambda object type's members are what the lambda captures. The captures 
are just a fancy way to define a constructor. But, seeing as the captures 
cannot be directly accessed (they can only shadow, and are the only way to 
shadow a variable in the language), you don't have to know that.

Once this lambda object type has been created, an object of that type is 
immediately created. Since you cannot know its identity, you cannot make 
multiple. That's where the "singleton" part comes in. There only exists one 
lambda object for each lambda expression. 

Hopefully this clears up some confusion about how lambda expressions are 
handled.


The usual use is to use it to define functions.

```
trait <T impl Number> {

}
```

A lambda expression is simply an instance of an 
anonymous class implementing a functional trait.



# Calling Conventions

Whenever is a method is called on a type, it is implicitly passed a pointer of 
that type as the argument's first method. That's how the `this` pointer is 
handled.

Take, for example, the following.
```
class Dog {
	String sound;
	Dog() { this.sound = "Bark"; }
	void bark(Dog d) { println(this.sound); }
}

Int main() { Dog().bark(); }
```

Then the above is equivalent to and generates the same code as below:

```
class Dog {
	String sound;
	Dog() { this.sound = "Bark"; }
}

void bark(Dog* d) { println(d.sound); }

Int main() {
	Dog d = Dog();
	bark(&d);
}
```


