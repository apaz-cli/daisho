State Registers:

Stack Machine's Stack
Type, Variable, Function Names and IDs, Line Numbers




Stack Machine:

```yaml
// TOKEN TYPES

PreProcessorToken:
    ImportStatement
Identifier:
    TypeIdentifier
    FunctionIdentifier
    VariableIdentifier
Keyword:
    ControlKeyword:
        IfKeyword
        ElseIfKeyword
        ElseKeyword
        ForKeyword
        WhileKeyword
        TryKeyword
        CatchKeyword
        FinallyKeyword
    JumpKeyword:
        ContinueKeyword
        BreakKeyword
    QualifierKeyword:
        CompileKeyword
    TypedefKeyword:
        ClassKeyword
        TemplateKeyword
        EnumKeyword
    TypeKeyword:
        BoolKeyword
        CharKeyword
        UCharKeyword
        ShortKeyword
        UShortKeyword
        IntKeyowrd
        UIntKeyword
        LongKeyword
        ULongKeyword
        FloatKeyword
        DoubleKeyword
        VoidKeyword
    PolyKeyword:
        ExtendsKeyword
        ImplementsKeyword
String:
    CharConstant
    StringConstant
Operator:
    OperatorEquals
    OperatorNot
    OperatorNotEquals
    OperatorDoubleEquals
    OperatorPlus
    OperatorMinus
    OperatorStar
    OperatorSlash
    OperatorPercent
    OperatorLeftArrow
    OperatorRightArrow
```
