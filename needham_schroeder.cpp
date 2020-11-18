// needham_schroeder.cpp : 
/*
	Implementation of Needham-Schroeder Protocol and Autokey Cypher for encryption and decryption; 
	Group No : 20
	Group Name : Team_07;
	Group Members:

		Name							Roll_No

	1.	Surender Kumar					BT17CSE082
	2.	Prince Kheriwal					BT17CSE056
	3.	Vikram Kumar					BT17CSE090

*/

#include <bits/stdc++.h>
#include<Windows.h>
using namespace std;

class Users {
private:
	string nonce;      // nonce -> Random character;
	string name;		// name of user;
	string rs;  // name of user to whom/who wants to communicate i.e. : receiver or sender;
	string secret_key;		//secret key known only to KDC and a particular key. It is unique for every user;
	string session_key;		//session key for a particular session is shared between all the users participatin in a session;
	string received_msg;
public:
	Users(string u) {
		transform(u.begin(), u.end(), u.begin(), ::toupper);
		name = u;
	}

	void set_name(string u) {
		transform(u.begin(), u.end(), u.begin(), ::toupper);
		name = u;	
	}

	string get_name() {
		return name;
	}

	void set_rs(string u) {
		transform(u.begin(), u.end(), u.begin(), ::toupper);
		rs = u;
	}

	string get_rs() {
		return rs;
	}

	void set_nonce(string u) {
		transform(u.begin(), u.end(), u.begin(), ::toupper);
		nonce = u;
	}

	string get_nonce() {
		return nonce;
	}

	void set_msg(string msg) {
		received_msg = msg;
	}

	string get_msg() {
		return received_msg;
	}

	void set_key(string sec_key) {
		secret_key = sec_key;
	}

	string get_key() {
		return secret_key;
	}

	void set_sess_key(string sess_key) {
		session_key = sess_key;
	}

	string get_sess_key() {
		return session_key;
	}

	bool authenticated(vector<string> v) {
		if (this->rs != v[1]) {
			cout << this->rs << " " << v[1] << endl;
			return false;
		}
		if (this->nonce != v[2]) {
			cout << this->nonce << " " << v[2] << endl;
			return false;
		}
		cout << this->get_name() << "'s nonce matched : " << v[2] << " == " << this->get_nonce() << endl;
		this->session_key = v[0];
		return true;
	}

	friend class KDC;	// KDC is declared as friend to each user;
};



class KDC {
private:
	string const arr = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
public:

	
	// autokey Decryption function;
	// Pi = (Ci - Ki) % 26;
	string autokeyDecryption(string ct, string k) {
		string pt = "";
		int n = ct.length();
		for (int i = 0; i < n; i++) {
			if (ct[i] != ' ') {
				int pi = (26 + (toupper(ct[i]) - 'A') - (toupper(k[0]) - 'A')) % 26;
				pt += arr[pi];
				k[0] = pt[i];
			}
			else {
				pt += ' ';
			}
		}
		return pt;
	}

	// autokey Encryption function
	//	Ci = (Pi + Ki) % 26;
	string autokeyEncryption(string pt, string k) {
		string ct = "";
		int n = pt.length();
		for (int i = 0; i < n; i++) {
			if (pt[i] != ' ') {
				int ci = ((toupper(pt[i]) - 'A') + (toupper(k[0]) - 'A')) % 26;
				ct += arr[ci];
				k[0] = pt[i];
			}
			else {
				ct += ' ';
			}
		}
		return ct;
	}

	// function generate session key for a particular session;
	// for each session session key is different to prevent the replay attack;
	vector<string> getSessionKey(Users* A, Users* B, string Ra, string EbR) {
		vector<string> ret;
		string s_key = "";
		s_key += arr[rand() % 26];
		string sa = autokeyEncryption(s_key, A->get_key()); //encrypt session key for user A using its secret key;
		string sb = autokeyEncryption(s_key, B->get_key()); //encrypt session key for user B using its secret key;

		/*
			ret contains  Ea{ Kab, B, Ra, Eb{ Kab, A, Rb } }
		*/
		ret.push_back(sa);
		ret.push_back(autokeyEncryption(B->get_name(), A->get_key()));
		ret.push_back(autokeyEncryption(Ra, A->get_key()));
		ret.push_back(autokeyEncryption(sb, A->get_key()));
		ret.push_back(autokeyEncryption(autokeyEncryption(A->get_name(), B->get_key()), A->get_key()));
		ret.push_back(autokeyEncryption(EbR, A->get_key()));

		return ret;
	}

	string generate_sec_key() {
		string key = "";
		key += arr[rand() % 26];
		return key;
	}

	string _nonce() {
		string nonce = "";
		nonce += arr[rand() % 26];
		return nonce;
	}

	friend class Users;
};

int main()
{
	srand(time(0));
	KDC* ca = new KDC();
	Users* A = new Users("Prince");
	Users* B = new Users("Vikram");

	cout << "_________________Starting NEEDHAM-SCHROEDER Protocol___________________\n\n" << endl;
	Sleep(1000); // function for delay of n milli seconds;
	bool foo = true;
	while (foo) {

		cout << "KDC distributing secret key to users......\n" << endl;
		//getting the secret keys for user A and B;
		A->set_key(ca->generate_sec_key());
		B->set_key(ca->generate_sec_key());

		//checking if secret keys of A and B are different or same;
		//Secret key must be different;
		while (A->get_key() == B->get_key()) {
			B->set_key(ca->generate_sec_key());
		}
		Sleep(1000); // function for delay of n milli seconds;

		//Opening new session between user A and user B
		//New session will be created succefully only if both the user's will have same session key;
		cout << "Trying to create a new session......\n" << endl;
		Sleep(1000); // function for delay of n milli seconds;


		//A and B choosing their nonce;
		A->set_nonce(ca->_nonce());
		B->set_nonce(ca->_nonce());

		//A seting B as receiver name;
		A->set_rs(B->get_name());
		B->set_rs(A->get_name());
		//A request B to choose it's nonce, B return it's nonce encrypted with B's secret key; 
		cout << A->get_name() << " requesting " << B->get_name() << " to choose its nonce Rb\n" << endl;
		Sleep(1000);

		cout << B->get_name() << " sending Eb{ Rb } to " << A->get_name() << "\n" << endl;
		string Ebn = ca->autokeyEncryption(B->get_nonce(), B->get_key()); // nonce Encrypted with B's secret key;
		Sleep(1000);

		//User A and B sends their secret keys to the Central Authority KDC to generate a session key which is 
		//Encrypted using A'secret_key for A and Encrypted for B using B'secret key; 
		string sa, sb;
		vector<string> vec;

		cout << A->get_name() << " requesting for session key from Central Authority (KDC). And send { A, B, Ra, Eb{ Rb } } to KDC" << "\n\n" << endl;

		vec = ca->getSessionKey(A, B, A->get_nonce(), Ebn);
		Sleep(1000); // function for delay of n milli seconds;
		cout << "KDC return Ea{ Kab, B, Ra, Eb{ Kab, A, Rb} }.....\n" << endl;
		Sleep(1000);


		cout << A->get_name() << " authenticating message send by KDC.....\n" << endl;
		Sleep(1000); // function for delay of n milli seconds;

		cout << A->get_name() << "'s Encrypted session key is : " << vec[0] << endl;

		//A decrypting msg send by KDC;
		for (int i = 0; i < (int)vec.size(); i++) {
			vec[i] = ca->autokeyDecryption(vec[i], A->get_key());
		}

		//A will authenticate by decrypting msg send by KDC by checking Ra(nonce) send and B's name;
		if (!A->authenticated(vec)) {
			cout << "Error: someone trying to steal information......" << endl;
			break;
		}

		Sleep(1000); // function for delay of n milli seconds;

		cout << A->get_name() << "'s Decrypted session key is : " << A->get_sess_key() << endl;
		Sleep(1000); // function for delay of n milli seconds;
		// A send Eb{ Kab, A, Rb } Eab{Ra} to B for authentication;

		vector<string> vb;
		for (int i = 3; i < 6; i++) {
			vb.push_back(vec[i]);
		}
		vb.push_back(ca->autokeyEncryption(A->get_nonce(), A->get_sess_key()));

		cout << "\n" << endl;
		//forwarding to B;
		cout << A->get_name() << " forwarding msg to " << B->get_name() << " for authentication\n" << endl;
		Sleep(1000); // function for delay of n milli seconds;

		cout << "\n" << endl;

		cout << B->get_name() << " received message from " << B->get_rs() << endl;
		cout << B->get_name() << "'s Encrypted session key is : " << vb[0] << endl;
		Sleep(1000); // function for delay of n milli seconds;

		//B decrypting msg send by A;
		for (int i = 0; i < 3; i++) {
			vb[i] = ca->autokeyDecryption(vb[i], B->get_key());
		}

		//B will authenticate by decrypting msg send by A by checking Rb(nonce) send and A's name;
		if (!B->authenticated(vb)) {
			cout << "Error: someone trying to steal information......" << endl;
			break;
		}

		cout << B->get_name() << "'s Decrypted session key is : " << B->get_sess_key() << endl;
		Sleep(1000); // function for delay of n milli seconds;
		//cout << "\n" << endl;

		cout << "Decrypting " << B->get_rs() << "'s nonce..." << endl;
		Sleep(1000);
		string nc = ca->autokeyDecryption(vb[3], B->get_sess_key());
		cout << "Nonce Ra received is : " << nc << endl;
		cout << "Sending " << B->get_rs() << " Eab{ Ra-1, Rb } \n" << endl;
		for (int i = 0; i< (int)nc.length(); i++) {
			int c = nc[i] - 'A';
			c = 25 + c;
			c %= 26;
			nc[i] = c + 'A';
		}
		B->set_nonce(ca->_nonce());

		vector<string> ba;
		ba.push_back(ca->autokeyEncryption(nc, B->get_sess_key()));
		ba.push_back(ca->autokeyEncryption(B->get_nonce(), B->get_sess_key()));
		Sleep(1000);

		cout << A->get_name() << " received message from " << A->get_rs() << endl;
		cout << "Decrypting Ra-1...." << endl;
		Sleep(1000);
		nc = ca->autokeyDecryption(ba[0], A->get_sess_key());
		for (int i = 0; i < (int)nc.length(); i++) {
			int c = nc[i] - 'A';
			c += 1;
			c %= 26;
			nc[i] = c + 'A';
		}
		if (nc != A->get_nonce()) {
			cout << "Error : nonce received is not matched. Session creating failed.\n" << endl;
			break;
		}
		cout << "Nonce matched" << endl;

		cout << "Decrypting " << A->get_rs() << "'s nonce...." << endl;
		Sleep(1000);
		nc = ca->autokeyDecryption(ba[1], B->get_sess_key());
		cout << "Nonce Rb received is : " << nc << endl;
		cout << "Sending " << A->get_rs() << " Eab{ Rb-1 } \n" << endl;
		for (int i = 0; i < (int)nc.length(); i++) {
			int c = nc[i] - 'A';
			c = 25 + c;
			c %= 26;
			nc[i] = c + 'A';
		}
		ba[0] = ca->autokeyEncryption(nc, A->get_sess_key());
		Sleep(1000);


		cout << B->get_name() << " received message from " << B->get_rs() << endl;
		cout << "Decrypting Rb-1...." << endl;
		Sleep(1000);
		nc = ca->autokeyDecryption(ba[0], B->get_sess_key());
		for (int i = 0; i < (int)nc.length(); i++) {
			int c = nc[i] - 'A';
			c += 1;
			c %= 26;
			nc[i] = c + 'A';
		}
		if (nc != B->get_nonce()) {
			cout << "Error : nonce received is not matched. Session creating failed.\n" << endl;
			break;
		}
		cout << "Nonce matched\n" << endl;
		if (A->get_sess_key() != B->get_sess_key()) {
			cout << "Session keys do not match. Can't create a new session" << endl;
		}
		Sleep(1000);

		cout << "Authentication is successfully completed\n";
		//session created successfully;
		cout << "__________________Session created successfully_________________ \n\n" << endl;
		Sleep(1000); // function for delay of n milli seconds;


		//User A sends the initial message to B;
		//session will expire when A and B stops communicating;
		bool communicate = true;
		int b = 0;
		while (communicate) {
			//user A will send initial message to user B;
			string msg, encrypted, decrypted;
			cout << A->get_name() << " : ";
			getline(cin, msg);
			if (msg == "bye") {
				b++;
			}
			if (b == 2) {
				break;
			}
			if (b == 1 && msg != "bye") {
				b = 0;
			}

			encrypted = ca->autokeyEncryption(msg, A->get_sess_key());
			cout << "Encrypting message....." << endl;
			Sleep(1000); // function for delay of n milli seconds;

			cout << "Encrypted msg is : " << encrypted << endl;
			Sleep(1000); // function for delay of n milli seconds;

			cout << "Sending ...... to " << B->get_name() << endl;
			B->set_msg(encrypted);
			Sleep(1000); // function for delay of n milli seconds;
			cout << "\n" << endl;


			//User B received encrypted message from A;
			//B decrypt and read it and then respond back to A;
			cout << B->get_name() << " received this message : " << B->get_msg() << endl;
			Sleep(1000); // function for delay of n milli seconds;

			cout << "Decrypting message....." << endl;
			decrypted = ca->autokeyDecryption(B->get_msg(), B->get_sess_key());
			Sleep(1000); // function for delay of n milli seconds;

			B->set_msg(decrypted);
			cout << "Decrypted message is : " << decrypted << endl;
			cout << "\n" << endl;
			Sleep(1000); // function for delay of n milli seconds;


			//Now B will send message back to A;
			cout << B->get_name() << " : ";
			getline(cin, msg);
			if (msg == "bye") {
				b++;
			}
			if (b == 2) {
				break;
			}
			if (b == 1 && msg != "bye") {
				b = 0;
			}
			encrypted = ca->autokeyEncryption(msg, B->get_sess_key());
			cout << "Encrypting message....." << endl;
			Sleep(1000); // function for delay of n milli seconds;

			cout << "Encrypted msg is : " << encrypted << endl;
			Sleep(1000); // function for delay of n milli seconds;

			cout << "Sending ...... to " << A->get_name() << endl;
			A->set_msg(encrypted);
			Sleep(1000); // function for delay of n milli seconds;
			cout << "\n" << endl;

			// A received message from B, decrypt it and read;
			cout << A->get_name() << " received this message : " << A->get_msg() << endl;
			Sleep(1000); // function for delay of n milli seconds;

			cout << "Decrypting message....." << endl;
			decrypted = ca->autokeyDecryption(A->get_msg(), A->get_sess_key());
			Sleep(1000); // function for delay of n milli seconds;

			A->set_msg(decrypted);
			cout << "Decrypted message is : " << decrypted << endl;
			cout << "\n" << endl;
			Sleep(1000); // function for delay of n milli seconds;

		}

		cout << "\n___________Session is closed successfully__________\n" << endl;

		string nw;
		cout << "Want to create another session (y/n) : ";
		cin >> nw;
		if (nw == "n") {
			foo = false;
		}
	}
	return 0;
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
