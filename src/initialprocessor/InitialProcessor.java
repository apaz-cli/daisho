package initialprocessor;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.Stack;
import java.util.stream.Stream;

public class InitialProcessor {

	/**
	 * 
	 * 
	 * Performs the following steps.
	 * 
	 * @see <a href=
	 *      "https://gcc.gnu.org/onlinedocs/cpp/Initial-processing.html#Initial-processing">GNU
	 *      Initial Processor Documentation</a>
	 * @param program The program before initial processing.
	 * @return program The program after initial processing.
	 */
	public static String run(String program) {

		// 1. The input file is read into memory and broken into lines.
		// Actually let's do this later.

		// 2. If trigraphs are enabled, they are replaced by their corresponding single
		// characters.
		// No trigraphs please.

		// 3. Continued lines are merged into one long line.
		program = program.replace("\\\n", "");

		// 4. All comments are replaced with single spaces.

		// Note comments are not recognized within string literals.

		// We accomplish this with a

		// Neutral state: 0
		// Inside string literal: 1
		// Inside sl comment: 2
		// Inside ml comment: 3
		
		// See the transition table in the language description.
		int neut = 0, str = 1, slc = 2, mlc = 3, smlc = 4, mslc = 5;
		int[][] transTable = new int[][] {
			new int[] {}
		}; 
		int state = 0;

		// program = program.replace("//.*\\\n", " ");
		// program = program.replace("/\\*.*/\\*", " ");

		// Now we can split by line.

		return program;
	}
}
