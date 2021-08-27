State Registers:

Stack Machine's Stack
Type, Variable, Function Names and IDs, Line Numbers




Stack Machine:

```yaml
/////////////////
// TOKEN TYPES //
/////////////////

PreProcessorToken:
    ImportStatement
Identifier:
    TypeIdentifier
    FunctionIdentifier
    VariableIdentifier
Keyword:
    ControlKeyword:
        IfKeyword
        ElifKeyword
        ElseKeyword
        ForKeyword
        WhileKeyword
        TryKeyword
        CatchKeyword
        FinallyKeyword
        SynchronizedKeyword
    JumpKeyword:
        ContinueKeyword
        BreakKeyword
    QualifierKeyword:
        NativeKeyword
        CompileKeyword
        StaticKeyword
    TypedefKeyword:
        StructKeyword
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
        InheritsKeyword
        ImplementsKeyword 
        AbstractKeyword
        DefaultKeyword
    OperatorKeyword:
        OperatorKeyword
        NewKeyword
        DestroyKeyword
String:
    CharConstant
    StringConstant
Operator:
    OperatorEquals
    OperatorNot
    OperatorPipe
    OperatorAmpersand
    OperatorDoublePipe
    OperatorDoubleAmpersand
    OperatorNotEquals
    OperatorDoubleEquals
    OperatorPlus
    OperatorMinus
    OperatorStar
    OperatorSlash
    OperatorPercent
    OperatorLessThan
    OperatorGreaterThan
    OperatorLeftShift
    OperatorRightShift
    OperatorPreincrement
    OperatorPostincrement
    OperatorPlusEquals
    OperatorMinusEquals
    OperatorStarEquals
    OperatorSlashEquals
```
