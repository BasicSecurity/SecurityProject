package be.pxl.encryption.backup;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.util.Arrays;
import org.apache.commons.io.*;

public class CopyOfConvert {
	public static byte[] toByteArray(Object o){
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		ObjectOutput out = null;
		try {
		  out = new ObjectOutputStream(bos);   
		  out.writeObject(o);
		  byte[] bytes = bos.toByteArray();
		  return bytes;
//		  byte[] cleanBytes = Arrays.copyOfRange(bytes, 6, bytes.length - 6);
//		  return cleanBytes;
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		} finally {
		  try {
		    if (out != null) {
		      out.close();
		    }
		  } catch (IOException ex) {
		    ex.printStackTrace();
		  }
		  try {
		    bos.close();
		  } catch (IOException ex) {
			  ex.printStackTrace();
		  }
		}
	}
	
	public static Object toObject(byte[] bytes){
		ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
		ObjectInput in = null;
		try {
		  in = new ObjectInputStream(bis);
		  Object o = in.readObject();   
		  return o;
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
			return null;
		} finally {
		  try {
		    bis.close();
		  } catch (IOException ex) {
			  ex.printStackTrace();
		  }
		  try {
		    if (in != null) {
		      in.close();
		    }
		  } catch (IOException ex) {
			  ex.printStackTrace();
		  }
		}
	}
}
