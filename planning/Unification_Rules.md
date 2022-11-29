
Ephemeral types:
Must immediately unify by being cast, stored, or used.
	NumLit
	StrLit
	EmptyList
	EmptyTuple
	EmptyDict

Primitive types:
	CType

Composite types:
	Struct
	Union
	Trait'
		Concrete, cannot be dereferenced
	Fn
	Pointer types
		VoidPtr cannot be dereferenced

Contextually bound types:
	Trait
	Type<T>
	T

Create a symtab for each namespace and scope from symbol + free tvars to
meaning.

Pull out all declarations and put them into symtabs for their namespace, as written in the AST.
Where a contextually bound type appears, create an object to track its use and replace the use with a 
pointer to that contextually bound type.
   Pull out:
	Declarations of types


A function definition
Expressions have types.


