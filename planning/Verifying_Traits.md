# Verifying Traits: A Proof System for Fine-Grained Reuse ∗

## Ferruccio Damiani

### Dipartimento di Informatica,

### Università di Torino, Italy

```
damiani@di.unito.it
```
## Johan Dovland,

## Einar Broch Johnsen

### Department of Informatics,

### University of Oslo, Norway

```
{johand,einarj}@ifi.uio.no
```
## Ina Schaefer

### Technische Universität

### Braunschweig, Germany

```
i.schaefer@tu-bs.de
```
## ABSTRACT

Traits have been proposed as a more flexible mechanism for code
structuring in object-oriented programming than class inheritance,
for achieving fine-grained code reuse. A trait originally developed
for one purpose can be modified and reused in a completely differ-
ent context. Formalizations of traits have been extensively studied,
and implementations of traits have started to appear in program-
ming languages. However, work on formally establishing proper-
ties of trait-based programs has so far mostly concentratedon type
systems. This paper proposes the first deductive proof system for
a trait-based object-oriented language. If a specificationfor a trait
can be given a priori, covering all actual usage of that trait, our
proof system is modular as each trait is analyzed only once. In
order to reflect the flexible reuse potential of traits, our proof sys-
tem additionally allows new specifications to be added to a trait in
anincrementalway which does not violate established proofs. We
formalize and show the soundness of the proof system.

## Categories and Subject Descriptors

D.1.5 [Programming Techniques]: Object-oriented Program-
ming; D.3.3 [Programming Languages]: Language Constructs
and Features; F.3.3 [Studies of Program Constructs]: Type Struc-
ture

## General Terms

Design, Languages, Theory

## Keywords

Proof System, Incremental Reasoning, Program Verification, Trait

∗The authors of this paper are listed in alphabetical or-

der. This work has been partially supported by the
Deutsche Forschungsgemeinschaft (DFG), the Italian MIUR
(PRIN 2009 DISCO), the German-Italian University Cen-
tre (Vigoni program) and the EU project FP7-231620 HATS
(http://www.hats-project.eu).

Permission to make digital or hard copies of all or part of this work for
personal or classroom use is granted without fee provided that copies are
not made or distributed for profit or commercial advantage and that copies
bear this notice and the full citation on the first page. To copy otherwise, to
republish, to post on servers or to redistribute to lists, requires prior specific
permission and/or a fee.
FTfJP’11,July 26, 2011, Lancaster, UK.
Copyright 2011 ACM 978-1-4503-0893-9/11/07 ...$10.00.

## 1. INTRODUCTION

```
With class inheritance, classes have two competing roles asgen-
erator of instances and as unit of reuse; in contrast,traitsare pure
units for fine-grained reuse [15]. Traits can be composed in an
arbitrary order and the composite unit (class or trait) has complete
control over conflicts that may arise and must solve them explicitly.
A trait is a set of methods, completely independent from any
class hierarchy. Thus, the common methods of a set of classes
can be factored into a trait. A trait originally developed for a par-
ticular purpose may be adapted and reused in a completely dif-
ferent context. This can lead to potentially undesired or conflict-
ing program behavior. Various formulations of traits have been
studied for JAVA-like languages (e.g., [9, 20, 23, 29, 31]). The re-
cent programming language FORTRESS[1] (which has no class-
based inheritance) has a trait construct, while the ‘trait’construct
of SCALA[25] is indeed a form of mixin. Research on ensuring
properties of trait-based programs has so far mostly considered type
systems (e.g., [9,20,28,29,31]). These approaches ensurethat the
composed program is type correct; i.e., all required fields and meth-
ods are present with the appropriate types.
This paper presents a compositional, deductive proof system for
a trait-based JAVA-like language [8]. This proof system can be used
to guarantee that programs obtained through the flexible adaptation
and composition of traits satisfy critical requirements, by reasoning
modularly and incrementally about traits, adaptation, andcomposi-
tion. As far as we know, no deductive proof system for trait-based
languages has been proposed so far.
The challenge in developing a deductive proof system for traits is
to support theflexibilityoffered by traits while providing anincre-
mentalandcompositionalreasoning system. Ideally, when traits
are composed in a class, the trait specifications already provide
enough information to ensure the contracts of the interfaces of that
class. In this case, the actual usage of the trait corresponds to its
originally intended usage as reflected in its original specification.
This specification can be established by analyzing the traitonly
once in a modular way. However, the original trait specification
may overly restrict the flexibility of trait reuse. In order to align
the proof system with this flexibility, traits are associated withsets
of possible specifications, and the applicable specification of a trait
depends on its context of composition. New specifications may be
addedincrementallyto a trait without violating previous specifi-
cations. When traits are composed in a class, the specification of
the composed traits is selected from compatible specifications of
its constituent traits. Hence, our proof system supports modular
reasoning for traits when applicable, but extends this modularity to
incremental reasoning when required for flexible trait reuse.
We develop an inference system for trait analysis which tracks
specification sets for traits, when traits are modified and composed.
```

ID ::= **interface** I **extends** I{S;} interface declaration
S ::= I m(Ix) method header
T ::= Tb|Tc trait name
TD ::= **trait** Tb **is** BTE| basic trait declaration and
**trait** Tc **is** CTE composed trait declaration
BTE ::= {F;S;M} basic trait expression
TAE ::= Tbao trait alteration expression
CTE ::= TAE|CTE 1 +CTE 2 composed trait expression
ao ::= [ **exclude** m]|[m **aliasAs** m]| trait alteration operation
[f **renameTo** f]|[m **renameTo** m]
F ::= I f field
M ::= S{ **return** e;} method
e ::= x|this.f|e.m(e)| **new** C(e)|(I)e expression
CD ::= **class** C **implements** I class declaration
**by** {F;} **and** CTE
Figure 1: The syntax of FRTJnf

```
This inference system adapts previous work on lazy behavioral sub-
typing [13], which developed an incremental inference system for
late bound method calls by separating the required and provided
behavior of methods, to trait modification and composition.The
approach does not depend on a particular program logic. For sim-
plicity, we use a Hoare-style notation to specify the pre- and post-
conditions of method definitions in terms of proof outlines and do
not consider, e.g., class or trait invariants.
Section 2 presents a trait-based JAVA-like language and Section 3
a specification notation for traits. Section 4 introduces the proposed
proof system for traits and discusses how it can be used to ver-
ify class and interface specifications. The formal inference system
for program analysis is introduced in Section 5, which also shows
soundness for the proof system. Related work is discussed inSec-
tion 6. Section 7 concludes the paper and discusses future work.
Proof sketches of the main results are available in [11].
```
## 2. A TRAIT-BASED LANGUAGE

```
In the formulation of traits considered in this paper, a trait con-
sists ofprovided methods(i.e., methods defined in the trait),re-
quired methodswhich parametrize the behavior, andrequired fields
that can be directly accessed in the body of the methods. Traits are
building blocks to compose classes and other, more complex,traits
using a suite of trait composition and alteration operations. Since
traits do not specify any state, a class assembled from traits has to
provide the required fields of its constituent traits.
For the purpose of this paper, we use FRTJnf (FEATHERWEIGHT
RECORD-TRAITJAVAnormal form), a calculus for traits within a
JAVA-like nominal type system. The syntax of FRTJnf is given in
Figure 1. A basic trait expression{F;S;M}providesthe methods
Mand declares the types of therequiredfieldsFand methodsS(that
can can be directly accessed by the bodies of the methodsM). The
symmetric sumoperation+merges two traits to form a new trait
and requires that the summed traits are disjoint, i.e., theydo not
provide identically named methods (they may require a same field
or method). Further, traits can be manipulated by the following trait
alteration operations. The operationexcludeforms a new trait by
removing a method from an existing trait. The operationaliasAs
forms a new trait by giving a new name to an existing method; in
particular, when a recursive method is aliased, its recursive invoca-
tion refers to the original method. The operationrenameTocreates
a new trait by renaming all occurrences of a required field name or
of a required/provided method name from an existing trait. Aclass
is assembled from a trait expression by providing the required fields
and a constructor. Classes further implement interfaces, specifying
the methods that can be called on an instance of the class. Forsim-
plicity, we omit the class constructors from the syntax: each class is
```
```
assumed to have a constructor of the formC(Jf){this.f=f;},
whereJfare all the fields of the class. In FRTJnf, the declaration
of types, behavior, and the generation of instances are completely
separated. Traits only play the role of units of behavior reuse and
are not types. Class-based inheritance is not present, so classes
only play the role of generators of instances. Interfaces are the
only source language types.
In the examples, when needed, we will use standard imperative
language features such as assignmentsthis.f=eandx = e(for
xdifferent fromthis), conditionals, and while-loops.
```
```
EXAMPLE2.1.As an ongoing example, we consider a simple
bank account implementation. The following traitTAccountpro-
vides the basic operations for inserting and withdrawing money:
trait TAccount is {
int bal; // req. field
bool validate(int a); // req. mtd.
void update(int y); // req. mtd.
void deposit(int x) { this .update(x);}
void withdraw(int id, int x){
boolean v = this .validate(id);
if (v) { this .update(-x);}}
}
```
```
A basic accountCAccountmay then be defined as follows, where
the additional traitTAuxdefines the auxiliary methods required by
TAccount:
interface IAccount {void deposit(int x);
void withdraw(int id, int x);}
trait TAux is {
int bal; int owner; // req. fields
void update(int y) { this .bal = this .bal + y}}
boolean validate(int id) { return (id == owner);}
}
class CAccount implements IAccount
by {int bal; int owner;} and TAccount + TAux
```
```
Since traits define flexible units for reuse, different account behav-
ior may be defined by combiningTAccountwith different traits.
For instance, the classCFeeAccountcharges an additional fee
whenever the balance is reduced:
trait TFee is {
int fee; int bal; // req. fields
void basicUpd(int y); // req. mtd.
void update(int y) { this .basicUpd(y);
if (y<0) { this .bal = this .bal - this .fee}}
}
class CFeeAccount implements IAccount
by {int bal; int owner; int fee;} and
TAccount + TFee + TAux[update renameTo basicUpd]
```
```
The public methods of an object are those listed in the inter-
faces implemented by its class; the other methods and fields are
private to the object and can only be accessed throughthis.
For instance, the only public members of classesCAccountand
CFeeAccountare the methodsdepositandwithdraw.
The semantics of a class composed from traits is specified
through theflattening principle[15, 23]. Flattening states that the
semantics of a method introduced in a class through a trait should
be identical to the semantics of the same method defined directly
within a class. The flattening functionJ·K(available in [11]) speci-
fies the semantics of FRTJnf by translating a FRTJnf class declara-
tion to a JAVAclass declaration, and a trait expression to a sequence
of method declarations.
FRTJnf is a subset of the prototypical language SWRTJ [8]. The
SWRTJ type system supports the type-checking of traits in isola-
tion from the classes or traits that use them, so that it is possible to
```

type-check a method defined in a trait only once (instead of having
to type-check it in every class using that trait). A distinguishing
feature of SWRTJ w.r.t. the other formulations of traits within a
JAVA-like nominal type system with this property [1, 20, 29, 31] is
that SWRTJ fully supports method exclusion and method/fieldre-
naming operations (such as the formulation of traits by Reppy and
Turon [28] in a structurally typed setting).
In particular, FRTJnf is a subset of FRTJ [6, 7], a minimal core
calculus (in the spirit of FEATHERWEIGHTJAVA[17]) for SWRTJ.
The FRTJnf subset of FRTJ represents a “normal form” that sim-
plifies the analysis, since it ensures that trait summation happens as
late as possible in a trait composition. In the sequel, we assume that
programs are well-typed according to the FRTJ type system [6,7].

## 3. SPECIFYING BASIC TRAITS

The proof system in this paper does not depend on a particular
program logic. For simplicity in the presentation, we use Hoare
triples{p}t{q}[16], wherepandqare assertions andtis a pro-
gram statement. Triples{p}t{q}have a standard partial correct-
ness semantics [3,4], adapted to the object-oriented setting; in par-
ticular, de Boer’s technique using sequences in assertionsaddresses
the issue of object creation [12]. Iftis executed in a state where the
preconditionpholds and the execution terminates, then the post-
conditionqholds, afterthas terminated. The derivation of triples
can be done in any suitable program logic. LetPLbe such a pro-
gram logic and let⊢PL{p}t{q}denote that{p}t{q}is derivable in
PL. We consider the following assertion language with assertions
adefined by

```
a::= this | return | null |f|x|z|op(a).
```
Here, **this** is the current object, **return** the current method’s re-
turn value,fa program field,xa formal parameter,za logical vari-
able, andopan operation on data types. Anassertion pair(p,q)is
a pair of assertions such thatpis a precondition andqa postcondi-
tion (for some sequence of program statements).
For a basic trait, the provided methods are annotated with asser-
tion pairs, specifying desired guarantees. A guarantee of aprovided
methodmmay crucially depend on the behavior of the methods
called bym. Consequently, we give aproof outline[26] for the
bodytofm, in which each method call is decorated with the behav-
ioral requirement needed bymin order to fulfill the guarantee, e.g.,
{r}n{s}for some called methodn. Given such a proof outline, it
is straightforward to verify that the guarantee holds formunder the
assumption that all requirements can be met, by applying therules
ofPL. LetO⊢PLt:(p,q)denote thatOisa valid proof outline
for the guarantee(p,q), i.e.,⊢PL{p}O{q}holds when we assume
that the requirements given inOare correct. Eachguaranteeof
mhas an associated set ofrequirementson other methods, derived
from the proof outline. The guarantee of a method together with the
associated set of requirements constitute amethod specification.
A trait is designed for flexible reuse. For this reason, it maybe
difficult to specify the methods in the trait in a way which covers
all possible future usage of the trait. There may be many possible
guarantees for its provided methods, depending on the context of
use. Different guarantees have different associated proofoutlines,
which give rise to different requirements on the called methods.
Thus, a provided method can have several specifications reflecting
different usage contexts. The initial specification reflects the origi-
nal intended usage of the method; new specifications may be added
if new ways of using the trait are found later. If the initial speci-
fication happens to suffice for later usage, this is the special case
whichcoincides with modular specification. Thespecification of a
traitconsists of the method specifications of its provided methods.

```
EXAMPLE3.1.Consider the withdraw method of trait
TAccountin Example 2.1. This method may be given the fol-
lowing two specifications, labelledw1andw2:
void withdraw(int id, int x){
boolean v = this .validate(id);
if (v) { this .update(-x);}}
// w1:(bal==b 0 ∧id==owner,bal==b 0 −x)
// reqs.:{bal==b 0 }update(y){bal==b 0 +y},
// {id==owner}validate(id){ return ==true}
// w2:(bal==b 0 ∧id 6 =owner,bal==b 0 )
// req.:{id 6 =owner}validate(id){ return ==false}
```
```
where trivial specifications, e.g., thatbalis not modified by
validate, are omitted for brevity. For traitTAux, we may supply
the following specifications, leading to no requirements:
trait TAux is { int bal; int owner; // req. fields
void update(int y) { this .bal = this .bal + y}}
//(bal=b 0 ,bal=b 0 +y)
```
```
boolean validate(int id) { return (id == owner);}
//(true, return == (id==owner))
}
```
## 4. COMPOSITIONAL VERIFICATION

```
The goal of our verification technique is to reason incrementally
about trait expressions while verifying trait-based programs. Due
to the flexible reuse potential of traits, we do not assume that a fixed
specification of a trait, given a priori, covers all potential usages of
that trait, although this is a special case of our more general incre-
mental approach. Instead, traits provide a set of possible method
specifications for each provided method that can be incrementally
extended. Thus, we devise compositional proof rules that apply to
sets of method specifications when traits are composed.
During the verification of a trait expression, atrait environment
is constructed to keep track of the specifications for the provided
methods. We assume that every method in an interface is anno-
tated with aninterface contractthat is an assertion pair describing
the behavior guaranteed by all implementations of that method to
reason about calls to methods on interface types. In the following,
we examine the different cases for constructing the trait environ-
ment for basic traits and composite traits constructed using the trait
composition and modification operations of FRTJnf.
Basic Traits.Letmbe a method provided by a basic traitT, and
let a guarantee ofmbe given by the assertion pair(p,q). The re-
quirements thatmimposes on the called methods, result in a proof
outlineOformwith guarantee(p,q). Using this proof outline, we
establish the guarantee(p,q)formby deductive techniques; e.g.,
using KeY [5] to verifyO⊢PLt:(p,q). Method calls may be ei-
therexternalorinternal. External calls rely on the interface of the
callee, so they may be analyzed directly using interface contracts.
For the proof outlineO, we collect the requirements{ri}ni{si}for
internal calls inOtogether with the guarantee(p,q)as a specifi-
cation formin the trait environment forT. A provided methodm
may have different guarantees depending on different requirements
on its called methods. Each of these guarantees is proven using a
different proof outline, leading to different specifications form.
Symmetric Sum of Traits.For two traits composed by symmet-
ric sum, we keep the distinction that each method specification has
particular assumptions on the required methods such that the trait
environment of the composed trait is the union of the trait environ-
ments of the single traits. In particular, method specifications are
kept in the trait environment even if their requirements cannot be
satisfied by the implementations found in other traits in thecom-
position. The reason is that the composed trait may be the subject
```

to later trait composition or modification operations. Thus, method
specifications that were unsatisfiable in the original composition
may again be satisfiable. However, if the composed trait is used in
a class definition, the analysis of the class ignores method specifi-
cations that are unnecessary in order to verify the interface contract
of the class, thereby selecting a set of consistent method specifica-
tions from the set of all provided method specifications fromthe
constituents of the composed trait.
Trait Modifiers.Excludinga method from a trait does not gen-
erate any proof obligations. The trait environment of the result-
ing trait is obtained from the previous trait environment byre-
moving the method specifications of the removed method.Alias-
ingdoes not generate proof obligations. The trait environmentfor
the resulting trait is obtained by copying the method specifications
of the aliased method. Renaming of methodsdoes not generate
proof obligations, but proof obligations for distinct methods may
now apply to the same method. The trait environment for the re-
sulting trait is obtained by consistently renaming the respective
method. Alsorenaming of fieldsdoes not generate proof obliga-
tions. The trait environment for the trait resulting by the trait al-
teration[f **renameTo** f′]is obtained by distinguishing different
cases. Iffdoes not occur in the previous trait, the trait environment
for the resulting trait is obtained directly from the previous trait en-
vironment. Otherwise, for each methodm, we consider whetherf′
occurs in the body ofmor not. In the former case, the method spec-
ifications ofmare simply dropped. In the latter case, the method
specifications ofmcontaining occurrences off′are dropped and,
in the other method specifications ofm, the occurrences offare
renamed tof′.

EXAMPLE4.1.Let the traitTAuxas specified in Example 3.1,
and consider the rename operationTAux[update **renameTo**
basicUpd]. The implementation ofvalidateis unaltered by
the operation, but theupdatemethod is renamed, and the speci-
fication given inTAuxapplies to the new method:

```
void basicUpd(int y) { this .bal = this .bal + y}}
//(bal=b 0 ,bal=b 0 +y)
```
Trait-based Classes.The main goal of the verification process
for trait-based programs is to show thata class implements the con-
tracts of its declared interfaces.It is necessary to show that every
public method exposed through an interface guarantees the con-
tract in that interface. This result should eventually follow from the
specification of the methods, as provided by the trait expression.
In the case where the trait specifications contain sufficientguaran-
tees, this follows directly. Otherwise, new method specifications
with additional guarantees may be added to trait specifications at
need, and method specifications are collected when a class isas-
sembled from traits by trait composition. For each added method
specification, the respective method must be reinspected with a new
proof outline. Such proof outlines may lead to new requirements
on internally called methods, which makes it necessary to supply
new proof outlines for these methods. This procedure repeats for
auxiliary internal calls until the analysis is complete. Remark that
all proofs which rely on the previously established guarantees of
the provided method remain valid. Thus, the presented approach is
incremental.
By the successful analysis of a class, the interface contract of ev-
ery public method is guaranteed by the trait specifications,and the
requirements on internal calls are guaranteed by the specifications
of the called methods.

```
EXAMPLE4.2.Consider the analysis of classCAccountin
Example 2.1, which is implemented byTAccount + TAux. As-
sume that in order to implement the interfaceIAccount, the proof
obligation:(bal=b 0 ,(id==owner⇒bal==b 0 −x)∧(id 6 =
owner⇒bal==b 0 ))must be verified for methodwithdrawin
TAccount. Since this obligation follows by entailment from the
guarantees ofw1andw2in Ex. 3.1, it suffices to ensure that the
requirements ofw1andw2are satisfied for the implementations
found inTAux, which is straightforward.
Consider next the analysis of classCFeeAccount, im-
plemented by TAccount + TFee + TAux[update
renameTo basicUpd], and assume that the proof obligation
(x> 0 ∧bal=b 0 ,(id==owner⇒bal==b 0 −x−fee)∧(id 6 =
owner⇒bal==b 0 ))is imposed onwithdrawby the interface
IFeeAccount. Remark that this proof obligation does not
follow from the guarantees ofw1andw2, and a new proof outline
must then be analyzed. It suffices to extend the specifications of
withdrawwith the following specificationw3:
void withdraw(int id, int x) {...}
// w3:(x> 0 ∧bal=b 0 ∧id=owner,bal==b 0 −x−fee)
// reqs.:{bal==b 0 ∧y< 0 }update(y){bal==b 0 +y−fee},
// {id==owner}validate(id){ return ==true}
```
```
Since the above proof obligation forwithdrawfollows by entail-
ment from the guarantees ofw2andw3, it suffices to verify the
requirements of these specifications. The only non-trivialrequire-
ment is the one toupdate, which can be verified by the following
specification inTFee:
trait TFee is {...
void update(int y) {...}
//(y< 0 ∧bal=b 0 ,bal=b 0 +y−fee)
// req.:{bal=b 0 }basicUpd(y){bal=b 0 +y}
}
```
```
This requirement follows from the guarantee ofbasicUpdas
given in Ex. 4.1.
```
## 5. THE INFERENCE SYSTEM

```
This section presentsPST(PL), aProofSystem forTrait-based
programs which is parametric in the underlying program logicPL.
The calculusPST(PL)relies on a sound program logicPL, and is
defined by the inference rules given in [11]. Judgements in the
calculus are of the formC,E ⊢P, whereEis atrait environ-
mentfor trait analysis,Cis aclass environmentfor keeping track
of declarations and specifications while analyzing classes, andP
is a sequence ofanalysis operations. Initially, the trait and class
environments are empty, andPis a sequence of trait and class
definitions. For each analyzed trait, the trait environmentEis ex-
tended with the trait definition and the specifications for the defined
methods. Thus, if the analysis of a traitTis initiated in some trait
environmentE, the successful analysis ofTwill lead to some trait
environmentE′which is an extension ofE. In this case. we say that
E′is the trait environmentresultingfrom the analysis. When ana-
lyzing classes, the class environment is extended similarly. Traits
and classes are analyzed based on the trait and class environments
resulting from the analysis of previous traits and classes.
Trait Analysis.Method guarantees are written as assertion pairs
(p,q)of typeGuar. To satisfy its guarantee, a methodmmay im-
poserequirementsof typeReqon the called methodsni, of the
form{r}ni{s}. Amethod specificationof typeSpecis a tuple
〈Guar,Set[Req]〉; i.e., a specification associates a set of require-
ments with the guarantee. If〈(p,q),R〉is a specification for some
methodm, we say thatmguarantees(p,q)assuming that the re-
quirementsRare satisfied for the called methods. Method specifi-
```

cations may be decomposed by the functionsguar:Spec→Guar
andreq:Spec→Set[Req]whereguar(〈(p,q),R〉), (p,q)and

req(〈(p,q),R〉),R. These functions are straightforwardly lifted
to sets of method specifications, returning sets of guarantees and
requirements, respectively. Given a proof outlineO, the function
reqs(O)returns the set of requirements occurring inO. Trait envi-
ronmentsEof typeEnvare defined as follows:

DEFINITION5.1 (TRAIT ENVIRONMENTS).A trait environ-
mentE:Env consists of two mappings TE and SE, where TE:
TAE→BTEand SE:TAE×Mid→Set[Spec].

MappingTEtakes a trait alteration expression and returns a ba-
sic trait expression, and mappingSE takes a trait alteration ex-
pression and a method name and returns a set of method specifi-
cations. For each basic trait of the form **trait** Tb **is** {F;S;M},
theTEmapping is extended with the definition of the trait, and
each user given guarantee leads to a specification recorded by
theSEmapping. If for instance a guarantee(p,q)is given for
methodI m(Ix){t}, a proof outlineOmust be supplied such that
O⊢PLt:(p,q), and the specification〈(p,q),reqs(O)〉is included
in the setSE(Tb,m). Remark that the actual implementation that an
internal call will bind to is not known when the trait is defined, since
method binding depends on how the trait is used to form classes.
Consequently, the imposed requirements are not verified with re-
gard to any implementation during trait analysis; Requirements are
only verified at need when the specification is actually used dur-
ing class analysis. When analyzing a composed trait of the form
**trait** Tc **is** TAE 1 +.. .+TAEn, where eachTAEiis of the form
Tbiaoi, properties for eachTAEiis remembered by the trait envi-
ronment. By the successful analysis ofTc, the mappingTEtakes
TAEito a basic trait definition containing the methods provided by
TAEi, andSEcontains specifications for these methods. These en-
tities are derived by manipulating the entities ofTbiaccording to
the modifiersaoias described in [11].
For each specification〈(p,q),R〉included inSE(TAE,m), the in-
ference system for trait analysis ensures thatmis provided byTAE
and that there exists a verified proof outlineOfor the bodytofm
such thatO⊢PLt:(p,q)wherereqs(O) =R.
Class Analysis. In addition to the trait environmentE, class
analysis builds a class environment reflecting the definitions and
specifications of classes. Classes are represented by a unique name
and a tuple〈I,CTE,F〉of typeClass.

DEFINITION5.2 (CLASS ENVIRONMENTS).A class envi-
ronmentC consists of two mappings DCand SC, where DC:
Cid7→Class, and SC:Cid×Mid7→Set[Spec].

Here,DCreflects the definitions of verified classes, andSCre-
flects their verified specifications. The main purpose of the class
environment is to record the method specifications used to establish
the contracts of the implemented interfaces; The analysis of class
**class** C **implements** I **by** {F;} **and** TAE 1 +.. .+TAEnis
driven by contracts ofI. By type-safety, we have that each pro-
vided methodmis defined in exactly oneTAEi. Upon the success-
ful analysis ofC, each interface contract for some provided method
mfollows byentailmentfrom the guarantees ofSC(C,m). Ifmis
provided byTAEi, the interface contracts are ensured by reusing
already verified specifications contained inSE(TAEi,m), and possi-
bly extendingSE(TAEi,m)with new specifications if needed. Thus,
SC(C,m)contains the subset ofSE(TAEi,m)that is actually used to
verify the current class. In addition, the requirements imposed by
the used specifications are analyzed with regard to the implemen-
tation they bind to forC. Thus, if〈(p,q),R〉 ∈SC(C,m), then each

```
requirement{r}n{s} ∈Rfollows by entailment from the guaran-
tees ofSC(C,n). The definition of the entailment relation_can
be found in [11,13].
Soundness. When reasoning about a set of mutually recur-
sive methods, the guarantees in the specifications of all meth-
ods are assumed to hold in order to verify the body of each
methods (e.g., [4]). We now extend this approach to define
theconsistency of a set of proof outlines for methods in a
flattened class with given interfaces. The flattened versionof
class C implements I by {Jf;} and CTEis given by
class C implements I{Jf;C(Jf){this.f=f;}M}as de-
fined in [11].
```
```
DEFINITION5.3 (CONSISTENCY).Consider the flattened
class class C implements I{Jf;C(Jf){this.f=f;}M}.
For each methodm∈Mwith method body t, let Smbe a set of
method specifications such that for each〈(p,q),R〉 ∈Sm, there ex-
ists a proof outline O where O⊢PLt:(p,q)andR=reqs(O). The
specifications SMareconsistentiff, for allm∈M:
```
```
1. ∀{r}m{s} ∈contracts(I).guar(Sm)_(r,s)
2. ∀〈(p,q),R〉 ∈Sm.∀{r}n{s} ∈R.guar(Sn)_(r,s)
```
```
Here, the first condition expresses that the interface contracts are
satisfied, whereas the second condition expresses that the require-
ments of all internal calls are satisfied. Previous work [13]defines
a sound calculus for analyzing single inheritance class hierarchies.
Given a consistent set of specifications, the analysis of a flattened
class succeeds in this calculus. In order to ensure soundness of
PST(PL), it thereby suffices to prove that the successful analysis of
some classCleads to a consistent set of specifications for the flat-
tened version ofC. The proof of this theorem can be found in [11].
```
```
THEOREM5.4.For a given class class C implements I
by {F;} and CTE, if the successful analysis ofCin PST(PL) leads
to a class environmentC, then the set of method specifications for
CinCare consistent for the flattened version ofC.
```
## 6. RELATED WORK

```
An important factor for the success of class-based object-
oriented programming is the inheritance mechanism to structure
and reuse code.Single inheritanceis the best supported by formal
systems for program analysis. In the context of single inheritance,
behavioral reasoning about extensible class hierarchies with late
bound method calls is often performed in the context ofbehavioral
subtyping(see, e.g., [2, 19, 21, 27]). Behavioral subtyping is an in-
cremental reasoning strategy in the sense that a subclass may be
analyzed in the context of previously defined classes. In order to
avoid reverification of superclasses, method overridings must pre-
serve the specifications of overridden methods. This approach has
also been used for SCALA’s ‘trait’ construct, but “significantly re-
duce the applicability and thereby benefits of traits” [30]. Lazy
behavioral subtyping[13] is an incremental reasoning strategy for
more flexible code reuse than behavioral subtyping. With lazy be-
havioral subtyping, therequirementsthat a method guarantee im-
poses on late bound method calls are identified, and the main idea
is that there is no need to preserve the full specifications ofoverrid-
den methods. In order to avoid reverification of superclass meth-
ods, only the weakerrequirementsimposed on late bound method
calls need to be preserved by method redefinitions in subclasses.
Multiple inheritanceis widely used in modeling notations such
as UML [10], to capture that a concept naturally inherits from sev-
eral other concepts. Versions of multiple inheritance are found
in C++, CLOS, Eiffel, and Ocaml. Creol [18] has proposed a
```

so-called healthy binding strategy which resolves horizontal name
conflicts by avoiding accidental overridings. The proof systems
presented in [14,22,24,32] are the only proof systems we know for
multiple inheritance class hierarchies. The work in [24] presents a
Hoare-style program logic for Eiffel that handles multipleinheri-
tance based on an existing program logic for single-inheritance by
extending the method lookup definition. In [22], method calls are
assumed to be fully qualified in order to avoid ambiguities, and
diamond inheritance is not considered. In [32], ambiguities are as-
sumed to be resolved by the programmer, a method can only be
inherited if it has the same implementation in all parents. In con-
trast, [14] applies lazy behavioral subtyping to multiple inheritance
and shows that healthy method binding is sufficient to allow in-
cremental reasoning about multiple inheritance class hierarchies.
The work in [14] resembles that of the current paper in the sepa-
ration of concerns between required and guaranteed assertions for
method calls and definitions, respectively. The main challenges
for reasoning about class hierarchies with multiple inheritance are
related to late bound method calls. In contrast, traits do not sup-
port late binding but the flexible composition of traits necessitates
a delayed selection of relevant method specifications. Technically,
this makes the two approaches fairly different. We are not aware of
any previous proposal for a deductive proof system for a trait-based
language.

## 7. CONCLUSION AND FUTURE WORK

This paper proposes a deductive proof system for trait-based
object-oriented programs, reflecting the fine-grained reuse poten-
tial of traits at the level of reasoning. The approach focusses on
verifying interface contracts. We plan an extension to additionally
consider invariants, both at the level of classes and traits. A trait
invariant may, for instance, capture relations between therequired
fields of a trait which extends the range of properties that can be
incrementally verified for trait-based programs. Further,we plan
to extend the KeY system [5] for deductive verification of JAVA
programs to SWRTJ programs and to implement the proof system
proposed in this paper within KeY.
Acknowledgements. We are grateful to Wolfgang Ahrendt,
Richard Bubel, Olaf Owe, and Volker Stolz for valuable discus-
sions on the subject of this work. We also thanks the anonymous
FTfJP referees for insightful comments and suggestions.

## 8. REFERENCES

```
[1] E. Allen, D. Chase, J. Hallett, V. Luchangco, G.-W.Maessen, S. Ryu,
G. Steele, and S. Tobin-Hochstad. The Fortress Language
Specification, V. 1.0, 2008.
[2] P. America. Designing an object-oriented programming language
with behavioural subtyping. In J. W. de Bakker, W.-P. de Roever, and
G. Rozenberg, editors,Foundations of Object-Oriented Languages,
pages 60–90. Springer, 1991.
[3] K. R. Apt. Ten years of Hoare’s logic: A survey — Part I.ACM
Transactions on Programming Languages and Systems,
3(4):431–483, Oct. 1981.
[4] K. R. Apt, F. S. de Boer, and E.-R. Olderog.Verification of
Sequential and Concurrent Systems. Texts and Monographs in
Computer Science. Springer, 3rd edition, 2009.
[5] B. Beckert, R. Hähnle, and P. H. Schmitt, editors.Verification of
Object-Oriented Software: The KeY Approach, volume 4334 of
LNCS. Springer, 2007.
[6] L. Bettini, F. Damiani, and I. Schaefer. Implementing software
product lines using traits. InSAC, pages 2096–2102. ACM, 2010.
[7] L. Bettini, F. Damiani, and I. Schaefer. Implementing Type-Safe
Software Product Lines using Records and Traits. TechnicalReport
RT 135, Dipartimento di Informatica, Università di Torino,2011.
Available athttp://www.di.unito.it/ ̃damiani/papers/tr-135-2011.pdf.
```
```
[8] L. Bettini, F. Damiani, I. Schaefer, and F. Strocco. A prototypical
Java-like language with records and traits. InPPPJ, pages 129–138.
ACM, 2010.
[9] V. Bono, F. Damiani, and E. Giachino. On Traits and Types in a
Java-like setting. InTCS (Track B), volume 273 ofIFIP, pages
367–382. Springer, 2008.
[10] G. Booch, J. Rumbaugh, and I. Jacobson.The Unified Modeling
Language User Guide. Addison-Wesley, 1999.
[11] F. Damiani, J. Dovland, E. B. Johnsen, and I. Schaefer. AProof
System for Fine-Grained Reuse (version with Appendix). Technical
Report RT 140, Dip. di Informatica, Università di Torino, 2011.
Available athttp://www.di.unito.it/ ̃damiani/papers/tr-140-2011.pdf.
[12] F. S. de Boer. A WP-calculus for OO. In W. Thomas, editor,
Proceedings of Foundations of Software Science and Computation
Structure, (FOSSACS’99), volume 1578 ofLNCS, pages 135–149.
Springer, 1999.
[13] J. Dovland, E. B. Johnsen, O. Owe, and M. Steffen. Lazy behavioral
subtyping.Journal of Logic and Algebraic Programming,
79(7):578–607, 2010.
[14] J. Dovland, E. B. Johnsen, O. Owe, and M. Steffen. Incremental
reasoning with lazy behavioral subtyping for multiple inheritance.
Science of Computer Programming, 76(10):915–941, 2011.
[15] S. Ducasse, O. Nierstrasz, N. Schärli, R. Wuyts, and A. P. Black.
Traits: A mechanism for fine-grained reuse.ACM Transactions on
Programming Languages and Systems, 28(2):331–388, 2006.
[16] C. A. R. Hoare. An Axiomatic Basis of Computer Programming.
Communications of the ACM, 12:576–580, 1969.
[17] A. Igarashi, B. Pierce, and P. Wadler. Featherweight Java: A minimal
core calculus for Java and GJ.ACM Transactions on Programming
Languages and Systems, 23(3):396–450, 2001.
[18] E. B. Johnsen, O. Owe, and I. C. Yu. Creol: A type-safe
object-oriented model for distributed concurrent systems.Theoretical
Computer Science, 365(1–2):23–66, Nov. 2006.
[19] G. T. Leavens and D. A. Naumann. Behavioral subtyping,
specification inheritance, and modular reasoning. Technical Report
06-20a, Department of Computer Science, Iowa State University,
Ames, Iowa, 2006.
[20] L. Liquori and A. Spiwack. Extending FeatherTrait Javawith
interfaces.Theoretical Computer Science, 398(1-3):243–260, 2008.
[21] B. H. Liskov and J. M. Wing. A behavioral notion of subtyping.ACM
Transactions on Programming Languages and Systems,
16(6):1811–1841, Nov. 1994.
[22] C. Luo and S. Qin. Separation logic for multiple inheritance.ENTCS,
212:27–40, April 2008.
[23] O. Nierstrasz, S. Ducasse, and N. Schärli. Flattening traits.JOT,
5(4):129–148, 2006.
[24] M. Nordio, C. Calcagno, P. Müller, and B. Meyer. A Sound and
Complete Program Logic for Eiffel. In M. Oriol, editor,
TOOLS-EUROPE 2009, volume 33 ofLecture Notes in Business and
Information Processing, pages 195–214, 2009.
[25] M. Odersky. The Scala Language Specification, version 2.4.
Technical report, Programming Methods Laboratory, EPFL, 2007.
[26] S. Owicki and D. Gries. An axiomatic proof technique forparallel
programs I.Acta Informatica, 6(4):319–340, 1976.
[27] A. Poetzsch-Heffter and P. Müller. A programming logicfor
sequential Java. In S. D. Swierstra, editor,8th European Symposium
on Programming Languages and Systems (ESOP’99), volume 1576
ofLNCS, pages 162–176. Springer, 1999.
[28] J. Reppy and A. Turon. A foundation for trait-based metapro-
gramming. InElectronic proceedings of FOOL/WOOD 2006, 2006.
[29] J. Reppy and A. Turon. Metaprogramming with traits. InECOOP,
volume 4609 ofLNCS, pages 373–398. Springer, 2007.
[30] M. Schwerhoff. Verifying Scala traits. Semester Report, Swiss
Federal Institute of Technology Zurich (ETH), Oct. 2010.
[31] C. Smith and S. Drossopoulou.Chai: Traits for Java-like languages.
InECOOP, volume 3586 ofLNCS, pages 453–478. Springer, 2005.
[32] S. van Staden and C. Calcagno. Reasoning about multiplerelated
abstractions with multistar. InOOPSLA ’10, pages 504–519. ACM,
2010.
```

