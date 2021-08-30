package optimizer;


@FunctionalInterface
public interface OptimizationPass {
	Object run();
}
