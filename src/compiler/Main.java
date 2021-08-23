package compiler;

import tokenizer.*;
import parser.*;
import optimizer.*;
import codegenerator.*;
import compiler.*;

public class Main {
	public static void main(String[] args) {
		String s = "\\";
		s = s.substring(0, s.length()-1);
		System.out.println(s);
	}
}
