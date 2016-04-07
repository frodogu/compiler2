package comp207p.main;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Iterator;
import java.util.ArrayList;
import java.util.Map;
import java.util.HashMap;
import java.util.Map.Entry;
import java.util.Arrays;
import java.util.*;
import java.lang.Class;
import java.math.*;

import org.apache.bcel.classfile.ClassParser;
import org.apache.bcel.classfile.Code;
import org.apache.bcel.classfile.JavaClass;
import org.apache.bcel.classfile.Method;
import org.apache.bcel.classfile.ExceptionTable;
import org.apache.bcel.classfile.CodeException;
import org.apache.bcel.generic.ClassGen;
import org.apache.bcel.generic.ConstantPoolGen;
import org.apache.bcel.generic.InstructionHandle;
import org.apache.bcel.generic.InstructionList;
import org.apache.bcel.util.InstructionFinder;
import org.apache.bcel.generic.MethodGen;
import org.apache.bcel.generic.TargetLostException;
import org.apache.bcel.generic.*;

public class ConstantFolder
{
	ClassParser parser = null;
	ClassGen gen = null;

	JavaClass original = null;
	JavaClass optimized = null;
	
	ArrayList<String> binaryOperationList = new ArrayList<>(Arrays.asList(
		"org.apache.bcel.generic.DADD",
        "org.apache.bcel.generic.FADD",
        "org.apache.bcel.generic.IADD",
        "org.apache.bcel.generic.LADD",
        "org.apache.bcel.generic.DDIV",
        "org.apache.bcel.generic.FDIV",
        "org.apache.bcel.generic.IDIV",
        "org.apache.bcel.generic.LDIV",
        "org.apache.bcel.generic.DCMPG",
        "org.apache.bcel.generic.DCMPL",
        "org.apache.bcel.generic.FCMPG",
        "org.apache.bcel.generic.FCMPL",
        "org.apache.bcel.generic.LCMP",
        "org.apache.bcel.generic.DMUL",
        "org.apache.bcel.generic.FMUL",
        "org.apache.bcel.generic.IMUL",
        "org.apache.bcel.generic.LMUL",
        "org.apache.bcel.generic.DREM",
        "org.apache.bcel.generic.FREM",
        "org.apache.bcel.generic.IREM",
        "org.apache.bcel.generic.LREM",
        "org.apache.bcel.generic.DSUB",
        "org.apache.bcel.generic.FSUB",
        "org.apache.bcel.generic.ISUB",
        "org.apache.bcel.generic.LSUB",
        "org.apache.bcel.generic.IAND",
        "org.apache.bcel.generic.LAND",
        "org.apache.bcel.generic.IXOR",
        "org.apache.bcel.generic.LXOR",
        "org.apache.bcel.generic.IOR",
        "org.apache.bcel.generic.LOR",
        "org.apache.bcel.generic.ISHL",
        "org.apache.bcel.generic.LSHL",
        "org.apache.bcel.generic.ISHR",
        "org.apache.bcel.generic.LSHR",
        "org.apache.bcel.generic.IUSHR",
        "org.apache.bcel.generic.LUSHR"
    ));

	ArrayList<String> unaryOperationList = new ArrayList<>(Arrays.asList(
        "org.apache.bcel.generic.DNEG",
        "org.apache.bcel.generic.FNEG",
        "org.apache.bcel.generic.INEG",
        "org.apache.bcel.generic.LNEG",
        "org.apache.bcel.generic.D2F",
        "org.apache.bcel.generic.D2I",
        "org.apache.bcel.generic.D2L",
        "org.apache.bcel.generic.F2D",
        "org.apache.bcel.generic.F2I",
        "org.apache.bcel.generic.F2L",
        "org.apache.bcel.generic.I2B",
        "org.apache.bcel.generic.I2D",
        "org.apache.bcel.generic.I2F",
        "org.apache.bcel.generic.I2L",
        "org.apache.bcel.generic.I2S",
        "org.apache.bcel.generic.L2D",
        "org.apache.bcel.generic.L2F",
        "org.apache.bcel.generic.L2I"
    ));

	ArrayList<String> constantLoadList = new ArrayList<>(Arrays.asList(
        "org.apache.bcel.generic.LDC",
        "org.apache.bcel.generic.LDC2_W",
        "org.apache.bcel.generic.LDC_W",
        "org.apache.bcel.generic.BIPUSH",
        "org.apache.bcel.generic.SIPUSH",
        "org.apache.bcel.generic.DCONST",
        "org.apache.bcel.generic.FCONST",
        "org.apache.bcel.generic.ICONST",
        "org.apache.bcel.generic.LCONST"
	));

	ArrayList<String> zeroCompareConditionList = new ArrayList<>(Arrays.asList(
        "org.apache.bcel.generic.IFEQ",
        "org.apache.bcel.generic.IFGE",
        "org.apache.bcel.generic.IFGT",
        "org.apache.bcel.generic.IFLE",
        "org.apache.bcel.generic.IFLT",
        "org.apache.bcel.generic.IFNE"
    ));

	ArrayList<String> doubleCompareConditionList = new ArrayList<>(Arrays.asList(
        "org.apache.bcel.generic.IF_ICMPEQ",
        "org.apache.bcel.generic.IF_ICMPGE",
        "org.apache.bcel.generic.IF_ICMPGT",
        "org.apache.bcel.generic.IF_ICMPLE",
        "org.apache.bcel.generic.IF_ICMPLT",
        "org.apache.bcel.generic.IF_ICMPNE"
    ));
	
	public ConstantFolder(String classFilePath)
	{
		try{
			this.parser = new ClassParser(classFilePath);
			this.original = this.parser.parse();
			this.gen = new ClassGen(this.original);
		} catch(IOException e){
			e.printStackTrace();
		}
	}

	/***
	判断Instruction 类型
	***/
	public boolean isBinaryOperation(Instruction ins)
	{
		if (ins == null)	
			return false;
		String cl = ins.getClass().getName();
		if (binaryOperationList.contains(cl))
		//cl is a binary instruction
			return true;
		//cl is not a binary instruction
		return false;
	}

	public boolean isUnaryInstruction(Instruction ins)
	{
		if (ins == null)
		    return false;
		String cl = ins.getClass().getName();
		if (unaryOperationList.contains(cl))
		    //cl is an unary instruction
		    return true;
		//cl is not an unary instruction
		return false;
	}

	public boolean isCPInstruction(Instruction ins)
	{
		if (ins == null)
		    return false;
		String cl = ins.getClass().getName();
		if (constantLoadList.contains(cl))
		    //cl is a cp instruction
		    return true;
		//cl is not a cp instruction
		return false;
	}

	public boolean isZCInstruction(Instruction ins)
	{
		if (ins == null)
		    return false;
		String cl = ins.getClass().getName();
		if (zeroCompareConditionList.contains(cl))
		    //cl is a cp instruction
		    return true;
		//cl is not a cp instruction
		return false;
	}

	public boolean isICInstruction(Instruction ins)
	{
		if (ins == null)
		    return false;
		String cl = ins.getClass().getName();
		if (doubleCompareConditionList.contains(cl))
		    //cl is a cp instruction
		    return true;
		//cl is not a cp instruction
		return false;
	}
	    
	/***
	Add result to all kinds of instructions
	***/
	public InstructionHandle addresulttocp(ConstantPoolGen cpgen, Object bottom, Object top, String ins, InstructionList instList, InstructionHandle handle, Map<Integer, Integer> exceptionmap)
	{

		//push  PUSH(ConstantPoolGen cp, value)
		InstructionHandle result = null;
	        try
	        {
	            switch (ins) {
					case "org.apache.bcel.generic.DADD": 
		                result = instList.insert(handle, new PUSH(cpgen, (double) bottom + (double) top));
		                break;
		        	case "org.apache.bcel.generic.FADD":
		                result = instList.insert(handle, new PUSH(cpgen, (float) bottom + (float) top));
		                break;
		            case "org.apache.bcel.generic.IADD":
		                result = instList.insert(handle, new PUSH(cpgen, (int) bottom + (int) top));
		            	break;
		            case "org.apache.bcel.generic.LADD":
		                result = instList.insert(handle, new PUSH(cpgen, (long) bottom + (long) top));
		                break;
					case "org.apache.bcel.generic.DDIV":
		        		result = instList.insert(handle, new PUSH(cpgen, (double) bottom / (double) top));
		                break;
			        case "org.apache.bcel.generic.FDIV":
						{
				            int index = cpgen.addFloat((float) bottom / (float) top);
				            result = instList.insert(handle, new LDC(index));
						}
		        		break;
	            	case "org.apache.bcel.generic.IDIV":
						{
			            	int index = cpgen.addInteger((int) bottom / (int) top);
			            	result = instList.insert(handle, new LDC(index));
						}
	            		break;
	            	case "org.apache.bcel.generic.LDIV":
	                	result = instList.insert(handle, new PUSH(cpgen, (long) bottom / (long) top));
	                	break;
	           	 	case "org.apache.bcel.generic.DCMPG":

						{
			                if ((double) bottom > (double) top)
			                    result = instList.insert(handle, new PUSH(cpgen, 1)); 
			                else if ((double) bottom == (double) top)
			                    result = instList.insert(handle, new PUSH(cpgen, 0));
			                else
			                    result = instList.insert(handle, new PUSH(cpgen, -1));
						}
	            		break;
					case "org.apache.bcel.generic.DCMPL":
						{
			                if ((double) bottom > (double) top)
			                    result = instList.insert(handle, new PUSH(cpgen, 1));
			                else if ((double) bottom == (double) top)
			                    result = instList.insert(handle, new PUSH(cpgen, 0));
			                else
			                    result = instList.insert(handle, new PUSH(cpgen, -1));
						}
	            		break;
	            	case "org.apache.bcel.generic.FCMPG":
						{
			                if ((float) bottom > (float) top)
			                    result = instList.insert(handle, new PUSH(cpgen, 1));
			                else if ((float) bottom == (float) top)
			                    result = instList.insert(handle, new PUSH(cpgen, 0));
			                else
			                    result = instList.insert(handle, new PUSH(cpgen, -1));
						}
	        		 	break;
	            	case "org.apache.bcel.generic.FCMPL":
						{
			                if ((float) bottom > (float) top)
			                    result = instList.insert(handle, new PUSH(cpgen, 1));
			                else if ((float) bottom == (float) top)
			                    result = instList.insert(handle, new PUSH(cpgen, 0));
			                else
			                    result = instList.insert(handle, new PUSH(cpgen, -1));
						}
		            	break;
	            	case "org.apache.bcel.generic.LCMP":
						{
			                if ((long) bottom > (long) top)
			                    result = instList.insert(handle, new PUSH(cpgen, 1));
			                else if ((long) bottom == (long) top)
			                    result = instList.insert(handle, new PUSH(cpgen, 0));
			                else
			                    result = instList.insert(handle, new PUSH(cpgen, -1));
						}
		            	break;
	            	case "org.apache.bcel.generic.DMUL":
	                	result = instList.insert(handle, new PUSH(cpgen, (double) bottom * (double) top));
	                	break;
	                case "org.apache.bcel.generic.FMUL":
		                result = instList.insert(handle, new PUSH(cpgen, (float) bottom * (float) top));
		                break;
		        	case "org.apache.bcel.generic.IMUL":
		                result = instList.insert(handle, new PUSH(cpgen, (int) bottom * (int) top));
		                break;
					case "org.apache.bcel.generic.LMUL":
		                result = instList.insert(handle, new PUSH(cpgen, (long) bottom * (long) top));
		                break;
		        	case "org.apache.bcel.generic.DREM":
		                result = instList.insert(handle, new PUSH(cpgen, (double) bottom % (double) top));
		                break;
		        	case "org.apache.bcel.generic.FREM":
		                result = instList.insert(handle, new PUSH(cpgen, (float) bottom % (float) top));
		                break;
		       		case "org.apache.bcel.generic.IREM":
		                result = instList.insert(handle, new PUSH(cpgen, (int) bottom % (int) top));
		                break;
		        	case "org.apache.bcel.generic.LREM":
		                result = instList.insert(handle, new PUSH(cpgen, (long) bottom % (long) top));
		                break;
		        	case "org.apache.bcel.generic.DSUB":
		                result = instList.insert(handle, new PUSH(cpgen, (double) bottom - (double) top));
		                break;
		        	case "org.apache.bcel.generic.FSUB":
		                result = instList.insert(handle, new PUSH(cpgen, (float) bottom - (float) top));
		                break;
		        	case "org.apache.bcel.generic.ISUB":
		                result = instList.insert(handle, new PUSH(cpgen, (int) bottom - (int) top));
		                break;
		  			case "org.apache.bcel.generic.LSUB":
		                result = instList.insert(handle, new PUSH(cpgen, (long) bottom - (long) top));
		                break;
	         		case "org.apache.bcel.generic.IAND":
		                result = instList.insert(handle, new PUSH(cpgen, (int) bottom & (int) top));
		                break;
		        	case "org.apache.bcel.generic.LAND":
		                result = instList.insert(handle, new PUSH(cpgen, (long) bottom & (long) top));
		                break;
		        	case "org.apache.bcel.generic.IXOR":
		                result = instList.insert(handle, new PUSH(cpgen, (int) bottom ^ (int) top));
		                break;
		        	case "org.apache.bcel.generic.LXOR":
		                result = instList.insert(handle, new PUSH(cpgen, (long) bottom ^ (long) top));
		                break;
		        	case "org.apache.bcel.generic.IOR":
		                result = instList.insert(handle, new PUSH(cpgen, (int) bottom | (int) top));
		                break;
		        	case "org.apache.bcel.generic.LOR":
		                result = instList.insert(handle, new PUSH(cpgen, (long) bottom | (long) top));
		                break;
		        	case "org.apache.bcel.generic.ISHL":
		                result = instList.insert(handle, new PUSH(cpgen, (int) bottom << (int) top));
		                break;
		        	case "org.apache.bcel.generic.LSHL":
		                result = instList.insert(handle, new PUSH(cpgen, (long) bottom << (int) top));
		                break;
		        	case "org.apache.bcel.generic.ISHR":
		                result = instList.insert(handle, new PUSH(cpgen, (int) bottom >> (int) top));
		                break;
		        	case "org.apache.bcel.generic.LSHR":
		                result = instList.insert(handle, new PUSH(cpgen, (long) bottom >> (int) top));
		                break;
		        	case "org.apache.bcel.generic.IUSHR":
		                result = instList.insert(handle, new PUSH(cpgen, (int) bottom >>> (int) top));
		                break;
		        	case "org.apache.bcel.generic.LUSHR":
		                result = instList.insert(handle, new PUSH(cpgen, (long) bottom >>> (int) top));
		                break;
	            }
	            return result;
	        } catch (Exception e)
	        {
	            return null;
	        }
	    }

	    public InstructionHandle addunaryresulttocp(ConstantPoolGen cpgen, Object bottom, String ins, InstructionList instList, InstructionHandle handle, Instruction instru)
	    {
	    			//push  PUSH(ConstantPoolGen cp, value)

	        InstructionHandle result = null;
	        switch (ins) {
		        case "org.apache.bcel.generic.DNEG":
		        	result = instList.insert(handle, new PUSH(cpgen, -(double) bottom));
		        	break;
		        case "org.apache.bcel.generic.FNEG":
					result = instList.insert(handle, new PUSH(cpgen, -(float) bottom));
		        	break;
		        case "org.apache.bcel.generic.INEG":
					result = instList.insert(handle, new PUSH(cpgen, -(int) bottom));
					break;
		        case "org.apache.bcel.generic.LNEG":
		            result = instList.insert(handle, new PUSH(cpgen, -(long) bottom));
		        	break;
		        case "org.apache.bcel.generic.D2F":
		            result = instList.insert(handle, new PUSH(cpgen, ((Number) bottom).floatValue()));
		        	break;
		        case "org.apache.bcel.generic.D2I":
		            result = instList.insert(handle, new PUSH(cpgen, ((Number) bottom).intValue()));
		        	break;
		        case "org.apache.bcel.generic.D2L":
		            result = instList.insert(handle, new PUSH(cpgen, ((Number) bottom).longValue()));
		        	break;
		        case "org.apache.bcel.generic.F2D":
		            result = instList.insert(handle, new PUSH(cpgen, ((Number) bottom).doubleValue()));
		        	break;
		        case "org.apache.bcel.generic.F2I":
		            result = instList.insert(handle, new PUSH(cpgen, ((Number) bottom).intValue()));
		        	break;
		        case "org.apache.bcel.generic.F2L":
		            result = instList.insert(handle, new PUSH(cpgen, ((Number) bottom).longValue()));
		        	break;
		        case "org.apache.bcel.generic.I2B":
		            result = instList.insert(handle, new PUSH(cpgen, ((Number) bottom).byteValue()));
		        	break;
		        case "org.apache.bcel.generic.I2D":
		            result = instList.insert(handle, new PUSH(cpgen, ((Number) bottom).doubleValue()));
		        	break;
		        case "org.apache.bcel.generic.I2F":
		            result = instList.insert(handle, new PUSH(cpgen, ((Number) bottom).floatValue()));
		        	break;
		        case "org.apache.bcel.generic.I2L":
		            result = instList.insert(handle, new PUSH(cpgen, ((Number) bottom).longValue()));
		        	break;
		        case "org.apache.bcel.generic.I2S":
		            result = instList.insert(handle, new PUSH(cpgen, ((Number) bottom).shortValue()));
		        	break;
		        case "org.apache.bcel.generic.L2D":
		            result = instList.insert(handle, new PUSH(cpgen, ((Number) bottom).doubleValue()));
		        	break;
		        case "org.apache.bcel.generic.L2F":
		            result = instList.insert(handle, new PUSH(cpgen, ((Number) bottom).floatValue()));
		        	break;
		        case "org.apache.bcel.generic.L2I":
		            result = instList.insert(handle, new PUSH(cpgen, ((Number) bottom).intValue()));
		        	break;
	        }
	        return result;
	    }

	    public Instruction addZCresulttocp(ConstantPoolGen cpgen, Object bottom, String ins, InstructionList instList, InstructionHandle handle, Instruction instru)
	    {
	    	//push  PUSH(ConstantPoolGen cp, value)

	        Instruction result = null;
			switch (ins) {
		        case "org.apache.bcel.generic.IFEQ":
			        {
			            if ((int) bottom == 0)
			                result = new ICONST(0);
			            else
			                result = new ICONST(1);
			        }
			        break;
		        case "org.apache.bcel.generic.IFGE":
			        {
			            if ((int) bottom >= 0)
			                result = new ICONST(0);
			            else
			                result = new ICONST(1);
			        }
			        break;
		        case "org.apache.bcel.generic.IFGT":
			        {
			            if ((int) bottom > 0)
			                result = new ICONST(0);
			            else
			                result = new ICONST(1);
			        }
			        break;
		        case "org.apache.bcel.generic.IFLE":
			        {
			            if ((int) bottom <= 0)
			                result = new ICONST(0);
			            else
			                result = new ICONST(1);
			        }
			        break;
		        case "org.apache.bcel.generic.IFLT":
			        {
			            if ((int) bottom < 0)
			                result = new ICONST(0);
			            else
			                result = new ICONST(1);
			        }
			        break;
		        case "org.apache.bcel.generic.IFNE":
			        {
			            if ((int) bottom != 0)
			                result = new ICONST(0);
			            else
			                result = new ICONST(1);
			        }
			        break;
		    }
	        return result;
	    }

	    public Instruction addICresulttocp(ConstantPoolGen cpgen, Object bottom, Object top, String ins, InstructionList instList, InstructionHandle handle, Instruction instru)
	    {
	        Instruction result = null;
			switch (ins) {
		        case "org.apache.bcel.generic.IF_ICMPEQ":
			        {
			            if ((int) bottom == (int) top)
			                result = new ICONST(0);
			            else
			                result = new ICONST(1);
			        }
			        break;
		        case "org.apache.bcel.generic.IF_ICMPGE":
			        {
			            if ((int) bottom >= (int) top)
			                result = new ICONST(0);
			            else
			                result = new ICONST(1);
			        }
			        break;
		        case "org.apache.bcel.generic.IF_ICMPGT":
			        {
			            if ((int) bottom > (int) top)
			                result = new ICONST(0);
			            else
			                result = new ICONST(1);
			        }
			        break;
		        case "org.apache.bcel.generic.IF_ICMPLE":
			        {
			            if ((int) bottom <= (int) top)
			                result = new ICONST(0);
			            else
			                result = new ICONST(1);
			        }
			        break;
		        case "org.apache.bcel.generic.IF_ICMPLT":
			        {
			            if ((int) bottom < (int) top)
			                result = new ICONST(0);
			            else
			                result = new ICONST(1);
			        }
			        break;
		        case "org.apache.bcel.generic.IF_ICMPNE":
			        {
			            if ((int) bottom != (int) top)
			                result = new ICONST(0);
			            else
			                result = new ICONST(1);
			        }
			        break;
		    }
	        return result;
	    }

	    public InstructionHandle addZCbranchresulttocp(ConstantPoolGen cpgen, Object bottom, String ins, InstructionList instList, InstructionHandle handle, IfInstruction instru)
	    {
	        InstructionHandle result = null;
			switch (ins) {
		        case "org.apache.bcel.generic.IFEQ":
		        	if((int) bottom == 0)
						result = instList.insert(handle, new GOTO(instru.getTarget()));
					break;
		        case "org.apache.bcel.generic.IFGE":
		        	if((int) bottom >= 0)
						result = instList.insert(handle, new GOTO(instru.getTarget()));
					break;
		        case "org.apache.bcel.generic.IFGT":
					if((int) bottom > 0)
						result = instList.insert(handle, new GOTO(instru.getTarget()));
					break;
		        case "org.apache.bcel.generic.IFLE":
		        	if((int) bottom <= 0)
						result = instList.insert(handle, new GOTO(instru.getTarget()));
					break;
		        case "org.apache.bcel.generic.IFLT":
		        	if((int) bottom < 0)
		            	result = instList.insert(handle, new GOTO(instru.getTarget()));
		        	break;
		        case "org.apache.bcel.generic.IFNE":
		        	if((int) bottom != 0)
		            	result = instList.insert(handle, new GOTO(instru.getTarget()));
		        	break;
		    }
	        return result;
	    }

	    public InstructionHandle addICbranchresulttocp(ConstantPoolGen cpgen, Object bottom, Object top, String ins, InstructionList instList, InstructionHandle handle, IfInstruction instru)
	    {
	        InstructionHandle result = null;
			switch (ins) {
		        case "org.apache.bcel.generic.IF_ICMPEQ":
		        	if((int) bottom == (int) top)
						result = instList.insert(handle, new GOTO(instru.getTarget()));
		            break;
		        case "org.apache.bcel.generic.IF_ICMPGE":
		        	if((int) bottom >= (int) top)
		                result = instList.insert(handle, new GOTO(instru.getTarget()));
		            break;
		        case "org.apache.bcel.generic.IF_ICMPGT":
		        	if((int) bottom > (int) top)
		                result = instList.insert(handle, new GOTO(instru.getTarget()));
		            break;
		        case "org.apache.bcel.generic.IF_ICMPLE":
		        	if((int) bottom <= (int) top)
		                result = instList.insert(handle, new GOTO(instru.getTarget()));
		            break;
		        case "org.apache.bcel.generic.IF_ICMPLT":
		        	if((int) bottom < (int) top)
		                result = instList.insert(handle, new GOTO(instru.getTarget()));
		            break;
		        case"org.apache.bcel.generic.IF_ICMPNE":
		        	if((int) bottom != (int) top)
		                result = instList.insert(handle, new GOTO(instru.getTarget()));
		            break;
			}
	        return result;
	    }

	/***
	检测循环
	***/
	    public boolean detectLoops(ClassGen cgen, ConstantPoolGen cpgen, Method method)
	    {
	        // Get the Code of the method, which is a collection of bytecode instructions
	        Code methodCode = method.getCode();
	        // Now get the actualy bytecode data in byte array,
	        // and use it to initialise an InstructionList
	        InstructionList instList = new InstructionList(methodCode.getCode());
	        // Initialise a method generator with the original method as the baseline
	        MethodGen methodGen = new MethodGen(method.getAccessFlags(), method.getReturnType(), method.getArgumentTypes(), null, method.getName(), cgen.getClassName(), instList, cpgen);
	        // InstructionHandle is a wrapper for actual Instructions
	        for (InstructionHandle handle : instList.getInstructionHandles())
	        {
	            // if branch instruction
	            if ((handle.getInstruction() instanceof BranchInstruction)&&(((BranchInstruction) handle.getInstruction()).getTarget().getPosition() < handle.getPosition()))
	                    return true;
	        }
	        return false;
	    }

	/***
	没有循环时候的优化
	***/
	    public boolean optimizeMethod(ClassGen cgen, ConstantPoolGen cpgen, Method method)
	    {
	        boolean unfinished = false;
	        // Get the Code of the method, which is a collection of bytecode instructions
	        Code methodCode = method.getCode();
	        // Now get the actualy bytecode data in byte array,
	        // and use it to initialise an InstructionList
	        InstructionList instList = new InstructionList(methodCode.getCode());
	        instList.setPositions();
	        // Initialise a method generator with the original method as the baseline
	        MethodGen methodGen = new MethodGen(method.getAccessFlags(), method.getReturnType(), method.getArgumentTypes(), null, method.getName(), cgen.getClassName(), instList, cpgen);
	        CodeException[] table = method.getCode().getExceptionTable();

	        Map<Integer, Integer> exceptionmap = new HashMap<Integer, Integer>();
	        int counter = 0;
	        for (InstructionHandle handle : instList.getInstructionHandles())
	        {
	            for (int m = 0; m < table.length; m++)
	            {

	                if (handle.getPosition() >= table[m].getStartPC() && handle.getPosition() <= table[m].getEndPC())
	                {
	                    handle.addAttribute("origpos", handle.getPosition());
	                    instList.findHandle(table[m].getHandlerPC()).addAttribute("origpos", instList.findHandle(table[m].getHandlerPC()).getPosition());
	                    exceptionmap.put(handle.getPosition(), instList.findHandle(table[m].getHandlerPC()).getPosition());
	                }
	            }
	        }

	        // InstructionHandle is a wrapper for actual Instructions
	        for (InstructionHandle handle : instList.getInstructionHandles())
	        {
	            // if unary instruction
	            if (isCPInstruction(handle.getInstruction())  )
	            {
	            	if (isUnaryInstruction(handle.getNext().getInstruction()) )
	            	{
	                // fold unary
		                unfinished = true;
		                Instruction ins = handle.getInstruction();
		                Object bottom = new Object();
		                if (ins instanceof LDC)
		                    bottom = ((LDC) ins).getValue(cpgen);
		                if (ins instanceof LDC2_W)
		                    bottom = ((LDC2_W) ins).getValue(cpgen);
		                if (ins instanceof ConstantPushInstruction)
		                    bottom = ((ConstantPushInstruction) ins).getValue();
		                addunaryresulttocp(cpgen, bottom, handle.getNext().getInstruction().getClass().getName(), instList, handle, handle.getNext().getInstruction());

		                try
		                {
		                    // delete the old one
		                    instList.delete(handle.getNext());
		                    instList.delete(handle);
		                } catch (TargetLostException e)
		                {
		                    // TODO Auto-generated catch block
		                    e.printStackTrace();
		                }
	            	}
	            }
	            // if binary instruction
	            else if (isCPInstruction(handle.getInstruction()) == true   )
	            {
	            	if (isCPInstruction(handle.getNext().getInstruction()) == true)
	            	{
	                // fold binary
	            		if (isBinaryOperation(handle.getNext().getNext().getInstruction()) == true)
	            		{
			                unfinished = true;
			                Object bottom = new Object(); //first is second on stack
			                Object top = new Object(); //second is top on stack

			                Instruction ins = handle.getInstruction();
			                if (ins instanceof LDC)
			                    bottom = ((LDC) ins).getValue(cpgen);
			                if (ins instanceof LDC2_W)
			                    bottom = ((LDC2_W) ins).getValue(cpgen);
			                if (ins instanceof ConstantPushInstruction)
			                    bottom = ((ConstantPushInstruction) ins).getValue();
			                    
			                Instruction ins2 = handle.getNext().getInstruction();
			                if (ins2 instanceof LDC)
			                    top = ((LDC) ins2).getValue(cpgen);
			                if (ins2 instanceof LDC2_W)
			                    top = ((LDC2_W) ins2).getValue(cpgen);
			                if (ins2 instanceof ConstantPushInstruction)
			                    top = ((ConstantPushInstruction) ins2).getValue();

			                InstructionHandle new_target = addresulttocp(cpgen, bottom, top, handle.getNext().getNext().getInstruction().getClass().getName(), instList, handle, exceptionmap);
			                if (new_target.getInstruction() instanceof GotoInstruction)
			                    delete_instructions(handle, ((GotoInstruction) new_target.getInstruction()).getTarget(), new_target, instList);
			                else
			                    replace_instructions(handle, handle.getNext().getNext().getNext(), new_target, instList);
		            	}
	            	}
	            }
	            // if zero comparison
	            else if (isCPInstruction(handle.getInstruction()) == true)
	            //basically this conditional is looking for the following pattern:
	            //load int
	            //zero compare
	            //ICONST_1
	            //goto someplace
	            //ICONST_0
	            //the last 2 checks if the branch instructions are to the correct instruction handles
	            {
	            	if (isZCInstruction(handle.getNext().getInstruction())  == true )
	            	{
	            		if (handle.getNext().getNext().getInstruction() instanceof ICONST  == true )
	            		{
	            			if (((int) ((ICONST) handle.getNext().getNext().getInstruction()).getValue()) == 1)
	            			{
	            				if (handle.getNext().getNext().getNext().getInstruction() instanceof GotoInstruction)
	            				{
	            					if (handle.getNext().getNext().getNext().getNext().getInstruction() instanceof ICONST)
	            					{
	            						if (((int) ((ICONST) handle.getNext().getNext().getNext().getNext().getInstruction()).getValue()) == 0)
	            						{
	            							if (((IfInstruction) handle.getNext().getInstruction()).getTarget() == handle.getNext().getNext().getNext().getNext())
	            							{
	            								if (((GotoInstruction) handle.getNext().getNext().getNext().getInstruction()).getTarget() == handle.getNext().getNext().getNext().getNext().getNext())
	            								{
				            						unfinished = true;
									                Instruction ins = handle.getInstruction();
									                Object bottom = new Object();
									                if (ins instanceof LDC)
									                    bottom = ((LDC) ins).getValue(cpgen);
									                if (ins instanceof ConstantPushInstruction)
									                    bottom = ((ConstantPushInstruction) ins).getValue();
									                Instruction newins = addZCresulttocp(cpgen, bottom, handle.getNext().getInstruction().getClass().getName(), instList, handle, handle.getNext().getInstruction());
									                try
									                {
									                    // delete the 5 instructions
									                    handle.getNext().getNext().getNext().getNext().setInstruction(newins);
									                    instList.delete(handle.getNext().getNext().getNext());
									                    instList.delete(handle.getNext().getNext());
									                    instList.delete(handle.getNext());
									                    instList.delete(handle);

									                } 
									                catch (TargetLostException e)
									                {
									                    // TODO Auto-generated catch block
									                    e.printStackTrace();
									                }
	            								}
	            							}
	            						}
						            	
	            					}
	            				}
	            			}
	            		}
	            	}
	                // fold comparison
	                
	            }
	            //if integer comparison
	            else if (isCPInstruction(handle.getInstruction())  )
	            //basically this conditional is looking for the following pattern:
	            //load int
	            //load int
	            //int compare
	            //ICONST_1
	            //goto someplace
	            //ICONST_0
	            //the last 2 checks if the branch instructions are to the correct instruction handles
	            {
	            	if (isCPInstruction(handle.getNext().getInstruction()))
	            	{
	            		if (isICInstruction(handle.getNext().getNext().getInstruction()))
	            		{
	            			if (handle.getNext().getNext().getNext().getInstruction() instanceof ICONST)
	            			{
	            				if (((int) ((ICONST) handle.getNext().getNext().getNext().getInstruction()).getValue()) == 1)
	            				{
	            					if (handle.getNext().getNext().getNext().getNext().getInstruction() instanceof GotoInstruction)
	            					{
	            						if (handle.getNext().getNext().getNext().getNext().getNext().getInstruction() instanceof ICONST)
	            						{
	            							if (((int) ((ICONST) handle.getNext().getNext().getNext().getNext().getNext().getInstruction()).getValue()) == 0 )
	            							{
	            								if (((IfInstruction) handle.getNext().getNext().getInstruction()).getTarget() == handle.getNext().getNext().getNext().getNext().getNext() )
	            								{
	            									if (((GotoInstruction) handle.getNext().getNext().getNext().getNext().getInstruction()).getTarget() == handle.getNext().getNext().getNext().getNext().getNext().getNext() )
	            									{
										                unfinished = true;
										                Object bottom = new Object(); //first is second on stack
										                Object top = new Object(); //second is top on stack
										                Instruction ins = handle.getInstruction();
										                if (ins instanceof LDC)
										                    bottom = ((LDC) ins).getValue(cpgen);
										                if (ins instanceof ConstantPushInstruction)
										                    bottom = ((ConstantPushInstruction) ins).getValue();
										                    
										                Instruction ins2 = handle.getNext().getInstruction();
										                if (ins2 instanceof LDC)
										                    top = ((LDC) ins2).getValue(cpgen);
										                if (ins2 instanceof ConstantPushInstruction)
										                    top = ((ConstantPushInstruction) ins2).getValue();
										                Instruction newins = addICresulttocp(cpgen, bottom, top, handle.getNext().getNext().getInstruction().getClass().getName(), instList, handle, handle.getNext().getNext().getInstruction());
										                try
										                {
										                    // delete the 5 instructions
										                    handle.getNext().getNext().getNext().getNext().getNext().setInstruction(newins);
										                    instList.delete(handle.getNext().getNext().getNext().getNext());
										                    instList.delete(handle.getNext().getNext().getNext());
										                    instList.delete(handle.getNext().getNext());
										                    instList.delete(handle.getNext());
										                    instList.delete(handle);
										                } catch (TargetLostException e)
										                {
										                    // TODO Auto-generated catch block
										                    e.printStackTrace();
										                }
	            									}
	            								}
	            							}
	            						}
	            					}
	            				}
	            			}
	            		}
	            	}
	                // fold binary

	            }
	            //no generic integer comparison branch optimisation due to existence of loops. May implement loop detection in future versions...
	        }
	        // setPositions(true) checks whether jump handles
	        // are all within the current method
	        instList.setPositions(true);
	        // set max stack/local
	        methodGen.setMaxStack();
	        methodGen.setMaxLocals();
	        // generate the new method with replaced iconst
	        Method newMethod = methodGen.getMethod();
	        // replace the method in the original class
	        cgen.replaceMethod(method, newMethod);
	        return unfinished;
	    }

	/***
	删除代码
	***/
	    public void delete_instructions(InstructionHandle handle, InstructionHandle new_target, InstructionHandle gotoins, InstructionList instList)
	    { //this function sets newtarget to the target of gotoins and deletes all instructions from currenthandle to new_target. If gotoins is null then currenthandle is handle and new_target is unchanged so it just deletes instructions from handle to new_target.
	        InstructionHandle currenthandle = handle;
	        if (gotoins != null)
	        {
	            new_target = ((GotoInstruction) gotoins.getInstruction()).getTarget();
	            currenthandle = gotoins;
	        }
	        ArrayList<InstructionHandle> handles_to_delete = new ArrayList<InstructionHandle>();
	        while (currenthandle != new_target)
	        {
	            handles_to_delete.add(currenthandle);
	            currenthandle = currenthandle.getNext();
	        }
	        for (int k = 0; k < handles_to_delete.size(); k++)
	        {
	            try
	            {
	                // delete the 5 instructions
	                instList.delete(handles_to_delete.get(k));
	            } catch (TargetLostException e)
	            { 
	                InstructionHandle[] targets = e.getTargets();
	                for (int i = 0; i < targets.length; i++)
	                {
	                    InstructionTargeter[] targeters = targets[i].getTargeters();
	                    for (int j = 0; j < targeters.length; j++)
	                        targeters[j].updateTarget(targets[i], new_target);
	                }
	            }
	        }
	    }

	    public void delete_instructions2(InstructionHandle handle, InstructionHandle new_target, InstructionHandle gotoins, InstructionList instList)
	    { //this function sets newtarget to the target of gotoins and deletes all instructions from currenthandle to new_target. If gotoins is null then currenthandle is handle and new_target is unchanged so it just deletes instructions from handle to new_target.
	        InstructionHandle currenthandle = handle;
	        if (gotoins != null)
	        {
	            new_target = ((GotoInstruction) gotoins.getInstruction()).getTarget();
	            currenthandle = gotoins;
	        }
	        ArrayList<InstructionHandle> handles_to_delete = new ArrayList<InstructionHandle>();
	        handles_to_delete.add(currenthandle);
	        while (currenthandle != new_target)
	        {
	            currenthandle = currenthandle.getNext();
	            handles_to_delete.add(currenthandle);
	        }
	        for (int k = 0; k < handles_to_delete.size(); k++)
	        {
	            try
	            {
	                // delete the 5 instructions
	                instList.delete(handles_to_delete.get(k));

	            } catch (TargetLostException e)
	            { 
	                InstructionHandle[] targets = e.getTargets();
	                for (int i = 0; i < targets.length; i++)
	                {
	                    InstructionTargeter[] targeters = targets[i].getTargeters();
	                    for (int j = 0; j < targeters.length; j++)
	                        targeters[j].updateTarget(targets[i], new_target);
	                }
	            }
	        }
	    }

 	/***
	修改代码
	***/
	    public void replace_instructions(InstructionHandle handle, InstructionHandle endhandle, InstructionHandle new_target, InstructionList instList)
	    { //this function sets deletes all instructions from currenthandle to endhandle not including endhandle.
	        InstructionHandle currenthandle = handle;
	        ArrayList<InstructionHandle> handles_to_delete = new ArrayList<InstructionHandle>();
	        while (currenthandle != endhandle)
	        {
	            handles_to_delete.add(currenthandle);
	            currenthandle = currenthandle.getNext();
	        }
	        for (int k = 0; k < handles_to_delete.size(); k++)
	        {
	            try
	            {
	                // delete the 5 instructions
	                instList.delete(handles_to_delete.get(k));
	            } catch (TargetLostException e)
	            { 
	                InstructionHandle[] targets = e.getTargets();
	                for (int i = 0; i < targets.length; i++)
	                {
	                    InstructionTargeter[] targeters = targets[i].getTargeters();
	                    for (int j = 0; j < targeters.length; j++)
	                        targeters[j].updateTarget(targets[i], new_target);
	                }
	            }
	        }
	    }

 	/***
	有循环时候的优化
	***/
	    public boolean optimizeMethodVars(ClassGen cgen, ConstantPoolGen cpgen, Method method) //Assume no loops in code, aggressively optimise
	    {
	        boolean unfinished = false;
	        // Get the Code of the method, which is a collection of bytecode instructions
	        Code methodCode = method.getCode();
	        // Now get the actualy bytecode data in byte array,
	        // and use it to initialise an InstructionList
	        InstructionList instList = new InstructionList(methodCode.getCode());
	        instList.setPositions();
	        // Initialise a method generator with the original method as the baseline
	        MethodGen methodGen = new MethodGen(method.getAccessFlags(), method.getReturnType(), method.getArgumentTypes(), null, method.getName(), cgen.getClassName(), instList, cpgen);
	        CodeException[] table = method.getCode().getExceptionTable();
	        Map<Integer, Integer> exceptionmap = new HashMap<Integer, Integer>();
	        Map<Integer, ObjectType> exceptiontypesmap = new HashMap<Integer, ObjectType>();
	        int counter = 0;
	        for (InstructionHandle handle : instList.getInstructionHandles())
	        {
	            for (int m = 0; m < table.length; m++)
	            {

	                if (handle.getPosition() >= table[m].getStartPC() && handle.getPosition() <= table[m].getEndPC())
	                {
	                    handle.addAttribute("origpos", handle.getPosition());
	                    instList.findHandle(table[m].getHandlerPC()).addAttribute("origpos", instList.findHandle(table[m].getHandlerPC()).getPosition());

	                    exceptionmap.put(handle.getPosition(), instList.findHandle(table[m].getHandlerPC()).getPosition());
	                    String exception = "java.lang.Exception";
	                    org.apache.bcel.generic.ObjectType catch_type = new org.apache.bcel.generic.ObjectType(exception);
	                    exceptiontypesmap.put(instList.findHandle(table[m].getHandlerPC()).getPosition(), catch_type);
	                }
	            }
	        }
	        // InstructionHandle is a wrapper for actual Instructions
	        Map<Integer, Number> varmap = new HashMap<Integer, Number>(); //maps local variables (referenced by an integer) to their values (typed as a Number)
	        boolean restart = true;
	        while (restart)
	        {
	            restart = false;
	            for (InstructionHandle handle : instList.getInstructionHandles())
	            {
	                // if ldc istore, put value into hashmap
	                if (isCPInstruction(handle.getInstruction()) && handle.getNext().getInstruction() instanceof StoreInstruction)
	                {
	                    // fold unary
	                    Instruction ins = handle.getInstruction();
	                    StoreInstruction stor = (StoreInstruction) handle.getNext().getInstruction();
	                    int varindex = stor.getIndex();
	                    Object bottom = new Object();
	                    if (ins instanceof LDC)
	                        bottom = ((LDC) ins).getValue(cpgen);
	                    if (ins instanceof LDC2_W)
	                        bottom = ((LDC2_W) ins).getValue(cpgen);
	                    if (ins instanceof ConstantPushInstruction)
	                        bottom = ((ConstantPushInstruction) ins).getValue();
	                    varmap.put(varindex, (Number) bottom); //put value of variable in map, then delete both instructions
	                }
	                //if there's a store instruction and we don't know what's being stored, delete it from the variable map
	                else if (handle.getInstruction() instanceof StoreInstruction && !(handle.getInstruction() instanceof ASTORE) && isCPInstruction(handle.getPrev().getInstruction()))
	                {
	                    // fold unary
	                    Instruction ins = handle.getPrev().getInstruction();
	                    StoreInstruction stor = (StoreInstruction) handle.getInstruction();
	                    int varindex = stor.getIndex();
	                    Object bottom = new Object();
	                    if (ins instanceof LDC)
	                        bottom = ((LDC) ins).getValue(cpgen);
	                    if (ins instanceof LDC2_W)
	                        bottom = ((LDC2_W) ins).getValue(cpgen);
	                    if (ins instanceof ConstantPushInstruction)
	                        bottom = ((ConstantPushInstruction) ins).getValue();
	                    varmap.put(varindex, (Number) bottom); //put value of variable in map, then delete both instructions
	                }
	                //if there's a store instruction and we don't know what's being stored, delete it from the variable map
	                else if (handle.getInstruction() instanceof StoreInstruction && !(handle.getInstruction() instanceof ASTORE) && !isCPInstruction(handle.getPrev().getInstruction()))
	                {
	                    int varindex = ((StoreInstruction) handle.getInstruction()).getIndex();
	                    varmap.remove(varindex);
	                    if (restart == true)
	                        break;
	                }
	                //replace load instructions if possible - if they are in the variable map
	                else if (handle.getInstruction() instanceof LoadInstruction && varmap.containsKey(((LoadInstruction) handle.getInstruction()).getIndex()))
	                {
	                    unfinished = true;
	                    restart = true;
	                    int key = ((LoadInstruction) handle.getInstruction()).getIndex();
	                    InstructionHandle new_target = instList.insert(handle, new PUSH(cpgen, varmap.get(key)));
	                    try
	                    {
	                        // delete the old one, this will cause a losttargetexception because the load instruction is likely referenced by other instructions. To deal with this point the old instructions to the new target
	                        instList.delete(handle);
	                    } catch (TargetLostException e)
	                    { 
	                        InstructionHandle[] targets = e.getTargets();
	                        for (int i = 0; i < targets.length; i++)
	                        {
	                            InstructionTargeter[] targeters = targets[i].getTargeters();
	                            for (int j = 0; j < targeters.length; j++)
	                                targeters[j].updateTarget(targets[i], new_target);
	                        }
	                    }
	                }
	                // if unary instruction
	                else if (isCPInstruction(handle.getInstruction()) && isUnaryInstruction(handle.getNext().getInstruction()))
	                {
	                    // fold unary
	                    unfinished = true;
	                    restart = true;
	                    Instruction ins = handle.getInstruction();
	                    Object bottom = new Object();
	                    if (ins instanceof LDC)
	                        bottom = ((LDC) ins).getValue(cpgen);
	                    if (ins instanceof LDC2_W)
	                        bottom = ((LDC2_W) ins).getValue(cpgen);
	                    if (ins instanceof ConstantPushInstruction)
	                        bottom = ((ConstantPushInstruction) ins).getValue();
	                    addunaryresulttocp(cpgen, bottom, handle.getNext().getInstruction().getClass().getName(), instList, handle, handle.getNext().getInstruction());
	                    try
	                    {
	                        // delete the old one
	                        instList.delete(handle.getNext());
	                        instList.delete(handle);

	                    } catch (TargetLostException e)
	                    {
	                        // TODO Auto-generated catch block
	                        e.printStackTrace();
	                    }
	                }
	                // if binary instruction
	                else if (isCPInstruction(handle.getInstruction()) && handle.getAttribute("NoOptimise") == null && isCPInstruction(handle.getNext().getInstruction()) && isBinaryOperation(handle.getNext().getNext().getInstruction()))
	                {
	                    // fold binarY
	                    unfinished = true;
	                    restart = true;
	                    Object bottom = new Object(); //first is second on stack
	                    Object top = new Object(); //second is top on stack
	                    Instruction ins = handle.getInstruction();
	                    if (ins instanceof LDC)
	                        bottom = ((LDC) ins).getValue(cpgen);
	                    if (ins instanceof LDC2_W)
	                        bottom = ((LDC2_W) ins).getValue(cpgen);
	                    if (ins instanceof ConstantPushInstruction)
	                        bottom = ((ConstantPushInstruction) ins).getValue();
	                    Instruction ins2 = handle.getNext().getInstruction();
	                    if (ins2 instanceof LDC)
	                        top = ((LDC) ins2).getValue(cpgen);
	                    if (ins2 instanceof LDC2_W)
	                        top = ((LDC2_W) ins2).getValue(cpgen);
	                    if (ins2 instanceof ConstantPushInstruction)
	                        top = ((ConstantPushInstruction) ins2).getValue();
	                    InstructionHandle new_target = addresulttocp(cpgen, bottom, top, handle.getNext().getNext().getInstruction().getClass().getName(), instList, handle, exceptionmap);
	                    if (new_target == null)
	                    { //exception thrown, do not optimise
	                        handle.addAttribute("NoOptimise", 1);
	                    } else
	                    {
	                        replace_instructions(handle, handle.getNext().getNext().getNext(), new_target, instList);
	                    }
	                }
	                // if zero comparison
	                else if (isCPInstruction(handle.getInstruction()) && isZCInstruction(handle.getNext().getInstruction()) && handle.getNext().getNext().getInstruction() instanceof ICONST && ((int) ((ICONST) handle.getNext().getNext().getInstruction()).getValue()) == 1 && handle.getNext().getNext().getNext().getInstruction() instanceof GotoInstruction && handle.getNext().getNext().getNext().getNext().getInstruction() instanceof ICONST && ((int) ((ICONST) handle.getNext().getNext().getNext().getNext().getInstruction()).getValue()) == 0 && ((IfInstruction) handle.getNext().getInstruction()).getTarget() == handle.getNext().getNext().getNext().getNext() && ((GotoInstruction) handle.getNext().getNext().getNext().getInstruction()).getTarget() == handle.getNext().getNext().getNext().getNext().getNext())
	                //basically this conditional is looking for the following pattern:
	                //load int
	                //zero compare
	                //ICONST_1
	                //goto someplace
	                //ICONST_0
	                //the last 2 checks if the branch instructions are to the correct instruction handles
	                {
	                    // fold comparison
	                    unfinished = true;
	                    restart = true;
	                    Instruction ins = handle.getInstruction();
	                    Object bottom = new Object();
	                    if (ins instanceof LDC)
	                        bottom = ((LDC) ins).getValue(cpgen);
	                    if (ins instanceof ConstantPushInstruction)
	                        bottom = ((ConstantPushInstruction) ins).getValue();
	                    Instruction newins = addZCresulttocp(cpgen, bottom, handle.getNext().getInstruction().getClass().getName(), instList, handle, handle.getNext().getInstruction());
	                    try
	                    {
	                        // delete the 5 instructions
	                        handle.getNext().getNext().getNext().getNext().setInstruction(newins);
	                        instList.delete(handle.getNext().getNext().getNext());
	                        instList.delete(handle.getNext().getNext());
	                        instList.delete(handle.getNext());
	                        instList.delete(handle);
	                    } catch (TargetLostException e)
	                    {
	                        // TODO Auto-generated catch block
	                        e.printStackTrace();
	                    }
	                }
	                //if integer comparison
	                else if (isCPInstruction(handle.getInstruction()) && isCPInstruction(handle.getNext().getInstruction()) && isICInstruction(handle.getNext().getNext().getInstruction()) && handle.getNext().getNext().getNext().getInstruction() instanceof ICONST && ((int) ((ICONST) handle.getNext().getNext().getNext().getInstruction()).getValue()) == 1 && handle.getNext().getNext().getNext().getNext().getInstruction() instanceof GotoInstruction && handle.getNext().getNext().getNext().getNext().getNext().getInstruction() instanceof ICONST && ((int) ((ICONST) handle.getNext().getNext().getNext().getNext().getNext().getInstruction()).getValue()) == 0 && ((IfInstruction) handle.getNext().getNext().getInstruction()).getTarget() == handle.getNext().getNext().getNext().getNext().getNext() && ((GotoInstruction) handle.getNext().getNext().getNext().getNext().getInstruction()).getTarget() == handle.getNext().getNext().getNext().getNext().getNext().getNext())
	                //basically this conditional is looking for the following pattern:
	                //load int
	                //load int
	                //int compare
	                //ICONST_1
	                //goto someplace
	                //ICONST_0
	                //the last 2 checks if the branch instructions are to the correct instruction handles
	                {
	                    // fold binary
	                    unfinished = true;
	                    restart = true;
	                    Object bottom = new Object(); //first is second on stack
	                    Object top = new Object(); //second is top on stack
	                    Instruction ins = handle.getInstruction();
	                    if (ins instanceof LDC)
	                        bottom = ((LDC) ins).getValue(cpgen);
	                    if (ins instanceof ConstantPushInstruction)
	                        bottom = ((ConstantPushInstruction) ins).getValue();
	                    Instruction ins2 = handle.getNext().getInstruction();
	                    if (ins2 instanceof LDC)
	                        top = ((LDC) ins2).getValue(cpgen);
	                    if (ins2 instanceof ConstantPushInstruction)
	                        top = ((ConstantPushInstruction) ins2).getValue();
	                    Instruction newins = addICresulttocp(cpgen, bottom, top, handle.getNext().getNext().getInstruction().getClass().getName(), instList, handle, handle.getNext().getNext().getInstruction());
	                    handle.getNext().getNext().getNext().getNext().getNext().setInstruction(newins);
	                    InstructionHandle new_target = handle.getNext().getNext().getNext().getNext().getNext();
	                    ArrayList<InstructionHandle> delhandles = new ArrayList<InstructionHandle>();
	                    delhandles.add(handle.getNext().getNext().getNext().getNext());
	                    delhandles.add(handle.getNext().getNext().getNext());
	                    delhandles.add(handle.getNext().getNext());
	                    delhandles.add(handle.getNext());
	                    delhandles.add(handle);
	                    for (int k = 0; k < delhandles.size(); k++)
	                    {
	                        try
	                        {
	                            // delete the 5 instructions
	                            instList.delete(delhandles.get(k));
	                        } catch (TargetLostException e)
	                        {
	                            InstructionHandle[] targets = e.getTargets();
	                            for (int i = 0; i < targets.length; i++)
	                            {
	                                InstructionTargeter[] targeters = targets[i].getTargeters();
	                                for (int j = 0; j < targeters.length; j++)
	                                    targeters[j].updateTarget(targets[i], new_target);
	                            }
	                        }
	                    }
	                }
	                // if generic zero comparison branch, optimise by deleting everything from goto to the target, goto included.
	                else if (isCPInstruction(handle.getInstruction()) && isZCInstruction(handle.getNext().getInstruction()))
	                //basically this conditional is looking for the following pattern:
	                //load int
	                //zero compare
	                {
	                    // fold comparison
	                    unfinished = true;
	                    restart = true;
	                    Instruction ins = handle.getInstruction();
	                    Object bottom = new Object();
	                    if (ins instanceof LDC)
	                        bottom = ((LDC) ins).getValue(cpgen);
	                    if (ins instanceof ConstantPushInstruction)
	                        bottom = ((ConstantPushInstruction) ins).getValue();
	                    InstructionHandle gotoins = addZCbranchresulttocp(cpgen, bottom, handle.getNext().getInstruction().getClass().getName(), instList, handle, (IfInstruction) handle.getNext().getInstruction());
	                    ///check if returned gotoins is null. if null that means we don't branch and run everything as normal
	                    InstructionHandle new_target = handle.getNext().getNext();
	                    delete_instructions(handle, new_target, gotoins, instList);
	                }
	                //if generic integer comparison branch, optimise by deleting everything from goto to the target, goto included.
	                else if (isCPInstruction(handle.getInstruction()) && isCPInstruction(handle.getNext().getInstruction()) && isICInstruction(handle.getNext().getNext().getInstruction()))
	                //basically this conditional is looking for the following pattern:
	                //load int
	                //load int
	                //int compare
	                {
	                    // fold binary
	                    unfinished = true;
	                    restart = true;
	                    Object bottom = new Object(); //first is second on stack
	                    Object top = new Object(); //second is top on stack
	                    Instruction ins = handle.getInstruction();
	                    if (ins instanceof LDC)
	                        bottom = ((LDC) ins).getValue(cpgen);
	                    if (ins instanceof ConstantPushInstruction)
	                        bottom = ((ConstantPushInstruction) ins).getValue();
	                    Instruction ins2 = handle.getNext().getInstruction();
	                    if (ins2 instanceof LDC)
	                        top = ((LDC) ins2).getValue(cpgen);
	                    if (ins2 instanceof ConstantPushInstruction)
	                        top = ((ConstantPushInstruction) ins2).getValue();
	                    InstructionHandle gotoins = addICbranchresulttocp(cpgen, bottom, top, handle.getNext().getNext().getInstruction().getClass().getName(), instList, handle, (IfInstruction) handle.getNext().getNext().getInstruction());
	                    InstructionHandle new_target = handle.getNext().getNext().getNext();
	                    delete_instructions(handle, new_target, gotoins, instList);
	                } else if (isICInstruction(handle.getInstruction()))
	                //if we can't optimize it, restart the loop
	                {
	                    restart = true;
	                    break;
	                }
	            }
	        }

	        for (InstructionHandle handle : instList.getInstructionHandles())
	        {
	            // if ldc istore, put value into hashmap
	            if (isCPInstruction(handle.getInstruction()) && handle.getNext().getInstruction() instanceof StoreInstruction)
	            {
	                // fold unary
	                InstructionHandle new_target = handle.getNext().getNext();
	                try
	                {
	                    // delete the old instructions. This will cause a targetlostexception, no problem just point the old instructions to the next instructionx
	                    instList.delete(handle.getNext());
	                } catch (TargetLostException e)
	                { 
	                    InstructionHandle[] targets = e.getTargets();
	                    for (int i = 0; i < targets.length; i++)
	                    {
	                        InstructionTargeter[] targeters = targets[i].getTargeters();
	                        for (int j = 0; j < targeters.length; j++)
	                            targeters[j].updateTarget(targets[i], new_target);
	                    }
	                }
	                try
	                {
	                    // delete the old instructions. This will cause a targetlostexception, no problem just point the old instructions to the next instructionx
	                    instList.delete(handle);
	                } catch (TargetLostException e)
	                { 
	                    InstructionHandle[] targets = e.getTargets();
	                    for (int i = 0; i < targets.length; i++)
	                    {
	                        InstructionTargeter[] targeters = targets[i].getTargeters();
	                        for (int j = 0; j < targeters.length; j++)
	                            targeters[j].updateTarget(targets[i], new_target);
	                    }
	                }
	            }
	        }
	        // setPositions(true) checks whether jump handles
	        // are all within the current method
	        instList.setPositions(true);
	        for (Entry<Integer, Integer> entry : exceptionmap.entrySet())
	        {
	            Integer key = entry.getKey();
	            Integer value = entry.getValue();
	            for (InstructionHandle handle : instList.getInstructionHandles())
	            {
	                if (handle.getAttribute("origpos") == key)
	                {
	                    for (InstructionHandle hand : instList.getInstructionHandles())
	                        if (hand.getAttribute("origpos") == value)
	                            methodGen.addExceptionHandler(handle, handle, hand, exceptiontypesmap.get(value));
	                }
	            }
	        }
	        // set max stack/local
	        methodGen.setMaxStack();
	        methodGen.setMaxLocals();
	        // generate the new method with replaced iconst
	        Method newMethod = methodGen.getMethod();
	        // replace the method in the original class
	        cgen.replaceMethod(method, newMethod);
	        return unfinished;
	    }
	
	/***
	主函数。
	***/
	public void optimize()
	{
		ClassGen cgen = new ClassGen(original);
		ConstantPoolGen cpgen = cgen.getConstantPool();
		// Implement your optimization here
		//First detect if code contains loops (backward jumps) or not. If contains loops, use simplefolding optimisation. If not, use dynamic variable optimisation.
	        boolean containsloops = false;
	        Method[] method = cgen.getMethods();
	        for (Method m : method)
	            //containsloops = containsloops || detectLoops(cgen, cpgen, m);
	        {
	        	if (detectLoops(cgen, cpgen, m)==true)
	        	{
	        		containsloops=true;
	        		break;
	        	}
	        }
	        if (containsloops)
	        { //simplefolding
		//Do note that in the build.xml file as of the time of this writing, in addition to the 3 tasks, the main and constantfolder class files are also optimised. This may cause confusion due to 5 statements being printed instead of the 3 expected....
	            boolean unfinished = true;
	            while (unfinished)
	            {
	                unfinished = false;
	                Method[] methods = cgen.getMethods();
	                for (Method m : methods)
	                {
	                	if (optimizeMethod(cgen, cpgen, m)==true)
	                	{
	                		unfinished=true;
	                	}
	                    //unfinished = unfinished || optimizeMethod(cgen, cpgen, m);
	                }
	            }
	        } else
	        { //dynamic variable folding
		//In the 3 printed out, the first of the 3 tasks is constantvariablefolding, the second is dynamicvariablefolding and the last one to appear is simplefolding due to alphabetical order.
	            Map<String, Map<InstructionHandle, InstructionHandle>> methodmap = new HashMap<String, Map<InstructionHandle, InstructionHandle>>();
	            Method[] methods = cgen.getMethods();
	            for (Method m : methods)
	                optimizeMethodVars(cgen, cpgen, m);
	        }
	        // we generate a new class with modifications
	        // and store it in a member variable
	        cgen.setMajor(45);
			this.optimized = gen.getJavaClass();
	}

	public void write(String optimisedFilePath)
	{
		this.optimize();
		try {
			FileOutputStream out = new FileOutputStream(new File(optimisedFilePath));
			this.optimized.dump(out);
		} catch (FileNotFoundException e) {
			// Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// Auto-generated catch block
			e.printStackTrace();
		}
	}
}
