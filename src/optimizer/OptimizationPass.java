package optimizer;

import parser.AST;

@FunctionalInterface
public interface OptimizationPass {
	public AST run(AST ast);
}
