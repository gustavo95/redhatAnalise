package analise;

import java.util.ArrayList;

//redhat
public class Main {

	public static void main(String[] args) throws Exception {
		Vulnerabilidades vul = new Vulnerabilidades();
		ArrayList<String> temp = vul.getTemp();

		for(String log : temp){
			System.out.println(log);
		}

	}

}
