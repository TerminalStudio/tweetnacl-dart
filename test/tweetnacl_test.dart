import 'package:test/test.dart';
import 'package:tweetnacl2/tweetnacl2.dart';
import 'dart:typed_data';
import "dart:convert";

final String BOB_PRIVATE_KEY =
    "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
final String BOB_PUBLIC_KEY =
    "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";

final String ALICE_PRIVATE_KEY =
    "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
final String ALICE_PUBLIC_KEY =
    "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
final String ALICE_MULT_BOB =
    "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";

final String BOX_NONCE = "69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37";
final String BOX_MESSAGE =
    "be075fc53c81f2d5cf141316ebeb0c7b5228c52a4c62cbd44b66849b64244ffc" +
        "e5ecbaaf33bd751a1ac728d45e6c61296cdc3c01233561f41db66cce314adb31" +
        "0e3be8250c46f06dceea3a7fa1348057e2f6556ad6b1318a024a838f21af1fde" +
        "048977eb48f59ffd4924ca1c60902e52f0a089bc76897040e082f93776384864" +
        "5e0705";
final String BOX_CIPHERTEXT =
    "f3ffc7703f9400e52a7dfb4b3d3305d98e993b9f48681273c29650ba32fc76ce" +
        "48332ea7164d96a4476fb8c531a1186ac0dfc17c98dce87b4da7f011ec48c972" +
        "71d2c20f9b928fe2270d6fb863d51738b48eeee314a7cc8ab932164548e526ae" +
        "90224368517acfeabd6bb3732bc0e9da99832b61ca01b6de56244a9e88d5f9b3" +
        "7973f622a43d14a6599b1f654cb45a74e355a5";

final String SECRET_KEY =
    "1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389";

final String SIGN_PRIVATE =
    "b18e1d0045995ec3d010c387ccfeb984d783af8fbb0f40fa7db126d889f6dadd";
final String SIGN_MESSAGE =
    "916c7d1d268fc0e77c1bef238432573c39be577bbea0998936add2b50a653171" +
        "ce18a542b0b7f96c1691a3be6031522894a8634183eda38798a0c5d5d79fbd01" +
        "dd04a8646d71873b77b221998a81922d8105f892316369d5224c9983372d2313" +
        "c6b1f4556ea26ba49d46e8b561e0fc76633ac9766e68e21fba7edca93c4c7460" +
        "376d7f3ac22ff372c18f613f2ae2e856af40";
final String SIGN_SIGNATURE =
    "6bd710a368c1249923fc7a1610747403040f0cc30815a00f9ff548a896bbda0b" +
        "4eb2ca19ebcf917f0f34200a9edbad3901b64ab09cc5ef7b9bcc3c40c0ff7509";
final String SIGN_PUBLIC =
    "77f48b59caeda77751ed138b0ec667ff50f8768c25d48309a8f386a2bad187fb";

void testHash() {
  final m0 = "Helloword, Am Tom ...";
  final b0 = utf8.encode(m0);
  final h0 =
      '7DB1C7083D2EF545D4D12B1A919C4E501F94F4C106EE5CF65C75093CFB39C421E39F2401EA9B1F0BCEBC792DF9019307B941524EE899A6EA1839BD1B306D5D2E';

  test('hash', () {
    print("\nsha512...@${DateTime.now().millisecondsSinceEpoch}");
    final hash = Hash.sha512(b0);
    print("...sha512@${DateTime.now().millisecondsSinceEpoch}");
    print("sha512@$m0/${b0.length}: $hash");
    expect(TweetNaclFast.hexEncodeToString(hash), h0);
  });
}

void testBoxKalium() {
  test('testBoxKalium: test vectors from Kalium project', () {
    // explicit nonce
    final theNonce = TweetNaclFast.hexDecode(BOX_NONCE);
    print("BOX_NONCE: \"${TweetNaclFast.hexEncodeToString(theNonce)}\"");

    // keypair A
    final ska = TweetNaclFast.hexDecode(ALICE_PRIVATE_KEY);
    final ka = Box.keyPair_fromSecretKey(ska);

    print("ska: \"${TweetNaclFast.hexEncodeToString(ka.secretKey)}\"");
    print("pka: \"${TweetNaclFast.hexEncodeToString(ka.publicKey)}\"");

    // keypair B
    final skb = TweetNaclFast.hexDecode(BOB_PRIVATE_KEY);
    final kb = Box.keyPair_fromSecretKey(skb);

    print("ska: \"${TweetNaclFast.hexEncodeToString(kb.secretKey)}\"");
    print("pka: \"${TweetNaclFast.hexEncodeToString(kb.publicKey)}\"");

    // peer A -> B
    final pabFast = new Box(kb.publicKey, ka.secretKey);

    // peer B -> A
    final pbaFast = new Box(ka.publicKey, kb.secretKey);

    // messages
    print("BOX_MESSAGE: \n" + BOX_MESSAGE.toUpperCase());
    print("BOX_CIPHERTEXT: \n" + BOX_CIPHERTEXT.toUpperCase());

    // cipher A -> B
    final cabFast =
        pabFast.box_nonce(TweetNaclFast.hexDecode(BOX_MESSAGE), theNonce);
    print("cabFast: \n" + TweetNaclFast.hexEncodeToString(cabFast));

    //!!! TweetNaclFast Box::box/open failed Kalium compatibility !!!
    expect(
      BOX_CIPHERTEXT.toUpperCase(),
      TweetNaclFast.hexEncodeToString(cabFast),
    );

    final mbaFastFast = pbaFast.open_nonce(cabFast, theNonce);
    print("mbaFastFast: \n" + TweetNaclFast.hexEncodeToString(mbaFastFast));

    //!!! TweetNaclFast Box::box/open failed Kalium compatibility !!!
    expect(
      BOX_MESSAGE.toUpperCase(),
      TweetNaclFast.hexEncodeToString(mbaFastFast),
    );
  });
}

void testBox() {
  test('box', () {
    // keypair A
    final ska = Uint8List(32);
    for (var i = 0; i < 32; i++) ska[i] = 0;
    final ka = Box.keyPair_fromSecretKey(ska);

    print("skat: ${ka.secretKey}");
    print("pkat: ${ka.publicKey}");

    // keypair B
    final skb = Uint8List(32);
    for (var i = 0; i < 32; i++) skb[i] = 1;
    final kb = Box.keyPair_fromSecretKey(skb);

    print("skbt: ${kb.secretKey}");
    print("pkbt: ${kb.publicKey}");

    // peer A -> B
    final pab = new Box.nonce(kb.publicKey, ka.secretKey, 0);

    // peer B -> A
    final pba = new Box.nonce(ka.publicKey, kb.secretKey, 0);

    // messages
    final m0 = "Helloword, Am Tom ...";

    // cipher A -> B
    final cab = pab.box(utf8.encode(m0));
    print("cabt: $cab");

    final mba = pba.open(Uint8List.fromList(cab));
    print("mbat: $mba");

    final nm0 = utf8.decode(mba);
    //box/open string failed
    expect(nm0, m0);

    // cipher B -> A
    // final b0 = Uint8List(100 * 1000000);
    // for (var i = 0; i < b0.length; i++) b0[i] = i;

    //print("big of 100M  box@${DateTime.now().millisecondsSinceEpoch}");
    //Uint8List cba = pba.box(b0);
    //Uint8List mab = pab.open(cba);
    //print("big of 100M open@${DateTime.now().millisecondsSinceEpoch}");
    ////big of 100M box/open binary failed
    //assert( b0 == mab);
  });
}

void testBoxNonce() {
  test('box nonce', () {
    // explicit nonce
    final theNonce = TweetNaclFast.makeBoxNonce();
    // final theNonce3 =
    //     TweetNaclFast.hexDecode(TweetNaclFast.hexEncodeToString(theNonce));
    //  print("BoxNonce Hex test Equal: " + "\"" + (theNonce == theNonce3) + "\"");
    print('BoxNonce: ${theNonce}');
    print('BoxNonce: ${TweetNaclFast.hexEncodeToString(theNonce)}');

    // keypair A
    final ska = Uint8List(32);
    for (var i = 0; i < 32; i++) ska[i] = 0;
    final ka = Box.keyPair_fromSecretKey(ska);

    print("skat: ${ka.secretKey}");
    print("pkat: ${ka.publicKey}");

    // keypair B
    final skb = Uint8List(32);
    for (var i = 0; i < 32; i++) skb[i] = 1;
    final kb = Box.keyPair_fromSecretKey(skb);

    print("skbt: ${kb.secretKey}");
    print("pkbt: ${kb.publicKey}");

    // peer A -> B
    final pab = Box(kb.publicKey, ka.secretKey);

    // peer B -> A
    final pba = Box(ka.publicKey, kb.secretKey);

    // messages
    final m0 = "Helloword, Am Tom ...";

    // cipher A -> B
    final cab = pab.box_nonce(utf8.encode(m0), theNonce);
    print("cabt: $cab");

    final mba = pba.open_nonce(Uint8List.fromList(cab), theNonce);
    print("mbat: $mba");

    final nm0 = utf8.decode(mba);
    //box/open string failed (with nonce)
    expect(nm0, m0);

    // cipher B -> A
    final b0 = Uint8List(6);

    print("box@${DateTime.now().millisecondsSinceEpoch}");
    final cba = pba.box_nonce(b0, theNonce);
    final mab = pab.open_nonce(cba, theNonce);
    print("open@${DateTime.now().millisecondsSinceEpoch}");
    //
    //  assertArrayEquals("box/open binary failed (with nonce)", b0, mab);
    expect(b0, equals(mab));
  });
}

void testSecretBox() {
  test('secret box', () {
    // shared key
    final shk = Uint8List(SecretBox.keyLength);
    for (var i = 0; i < shk.length; i++) shk[i] = 0x66;

    // peer A -> B
    final pab = SecretBox.nonce(shk, 0);

    // peer B -> A
    final pba = SecretBox.nonce(shk, 0);

    // messages
    var m0 = "Helloword, Am Tom ...";

    // cipher A -> B
    print("streess on secret box@$m0");

    for (int t = 0; t < 19; t++, m0 += m0) {
      final mb0 = utf8.encode(m0);

      print("\n\n\tstreess/${(mb0.length / 1000.0)}kB: $t times");

      /*String mb0t = "mb0/"+mb0.length + ": ";
			for (var i = 0; i < mb0.length; i ++)
				mb0t += " "+mb0[i];
			System.out.println(mb0t);
      */
      print("secret box ...@${DateTime.now().millisecondsSinceEpoch}");
      final cab = pab.box(mb0);
      print("... secret box@${DateTime.now().millisecondsSinceEpoch}");

      /*String cabt = "cab/"+cab.length + ": ";
			for (var i = 0; i < cab.length; i ++)
				cabt += " "+cab[i];
			System.out.println(cabt);
        */
      print("\nsecret box open ...@${DateTime.now().millisecondsSinceEpoch}");
      final mba = pba.open(cab);
      print("... secret box open@${DateTime.now().millisecondsSinceEpoch}");

      /*
			String mbat = "mba/"+mba.length + ": ";
			for (var i = 0; i < mba.length; i ++)
				mbat += " "+mba[i];
			System.out.println(mbat);
      */

      final nm0 = utf8.decode(mba);
      //secret box/open failed
      expect(nm0, m0);
    }
  });
}

void testSecretBoxNonce() {
  test('secret box nonce', () {
    // explicit nonce
    final theNonce = TweetNaclFast.makeSecretBoxNonce();
    print("SecretBoxNonce :$theNonce");

    // shared key
    final shk = Uint8List(SecretBox.keyLength);
    for (var i = 0; i < shk.length; i++) shk[i] = 0x66;

    // peer A -> B
    final pab = SecretBox(shk);

    // peer B -> A
    final pba = SecretBox(shk);

    // messages
    var m0 = "Helloword, Am Tom ...";

    // cipher A -> B
    print("stress on secret box with explicit nonce@" + m0);

    for (int t = 0; t < 19; t++, m0 += m0) {
      final mb0 = utf8.encode(m0);

      print("\n\n\tstreess/${(mb0.length / 1000.0)}kB: $t times");

      /*String mb0t = "mb0/"+mb0.length + ": ";
			for (var i = 0; i < mb0.length; i ++)
				mb0t += " "+mb0[i];
			System.out.println(mb0t);
      */
      print("secret box ...@${DateTime.now().millisecondsSinceEpoch}");
      final cab = pab.box_nonce(mb0, theNonce);
      print("... secret box@${DateTime.now().millisecondsSinceEpoch}");

      /*String cabt = "cab/"+cab.length + ": ";
			for (var i = 0; i < cab.length; i ++)
				cabt += " "+cab[i];
			System.out.println(cabt);
      */
      print("\nsecret box open ...@${DateTime.now().millisecondsSinceEpoch}");
      final mba = pba.open_nonce(cab, theNonce);
      print("... secret box open@${DateTime.now().millisecondsSinceEpoch}");

      /*
			String mbat = "mba/"+mba.length + ": ";
			for (var i = 0; i < mba.length; i ++)
				mbat += " "+mba[i];
			System.out.println(mbat);
      */

      final nm0 = utf8.decode(mba);
      //secret box/open failed
      expect(nm0, m0);
    }
  });
}

void testSign() {
  test('sign', () {
    // keypair A
    final ka = Signature.keyPair();

    // keypair B
    final kb = Signature.keyPair();

    // peer A -> B
    final pab = Signature(kb.publicKey, ka.secretKey);

    // peer B -> A
    final pba = Signature(ka.publicKey, kb.secretKey);

    // messages
    String m0 = "Helloword, Am Tom ...";

    // signature A -> B
    print("\nsign...@${DateTime.now().millisecondsSinceEpoch}");
    final sab = pab.sign(utf8.encode(m0));
    print("...sign@${DateTime.now().millisecondsSinceEpoch}");

    var sgt = "sign@" + m0 + ": ";
    for (var i = 0; i < Signature.signatureLength; i++) sgt += " ${sab[i]}";
    print(sgt);

    print("verify...@${DateTime.now().millisecondsSinceEpoch}");
    final oba = pba.open(sab);
    print("...verify@${DateTime.now().millisecondsSinceEpoch}");

    //"verify failed"
    expect(oba, isNotNull);
    var nm0 = utf8.decode(oba);
    //"sign failed"
    expect(nm0, m0);

    // keypair C
    final seed = Uint8List(Signature.seedLength);
    for (var i = 0; i < seed.length; i++) seed[i] = 0x66;

    final kc = Signature.keyPair_fromSeed(seed);

    print("skct: ${kc.secretKey}");
    print("pkct: ${kc.publicKey}");

    // self-signed
    final pcc = Signature(kc.publicKey, kc.secretKey);

    print("\nself-sign...@${DateTime.now().millisecondsSinceEpoch}");
    final scc = pcc.sign(utf8.encode(m0));
    print("...self-sign@${DateTime.now().millisecondsSinceEpoch}");

    var ssc = "self-sign@" + m0 + ": ";
    for (var i = 0; i < Signature.signatureLength; i++) ssc += " ${scc[i]}";
    print(ssc);

    print("self-verify...@${DateTime.now().millisecondsSinceEpoch}");
    final occ = pcc.open(scc);
    print("...self-verify@${DateTime.now().millisecondsSinceEpoch}");

    //"self-verify failed"
    expect(occ, isNotNull);
    nm0 = utf8.decode(occ);
    //"self-sign failed"
    expect(nm0, m0);
  });
}

void testSignDetached(String seedStr) {
  test('sign detached', () {
    print("seed:@${DateTime.now().millisecondsSinceEpoch}");

    final seed = TweetNaclFast.hexDecode(seedStr);
    final kp = Signature.keyPair_fromSeed(seed);

    final testString = "test string";
    final bytes = utf8.encode(testString);

    final s1 = Signature(null, kp.secretKey);
    print("\ndetached...@${DateTime.now().millisecondsSinceEpoch}");
    final signature = s1.detached(bytes);
    print("...detached@${DateTime.now().millisecondsSinceEpoch}");

    final s2 = Signature(kp.publicKey, null);
    print("\nverify...@${DateTime.now().millisecondsSinceEpoch}");
    final result = s2.detached_verify(bytes, signature);
    print("...verify@${DateTime.now().millisecondsSinceEpoch}");

    expect(result, isTrue);
  });
}

void main() {
  testHash();
  testBoxKalium();
  testBox();
  testBoxNonce();
  testSecretBox();
  testSecretBoxNonce();
  testSign();
  testSignDetached(
    "ac49000da11249ea3510941703a7e21a39837c4d2d5300daebbd532df20f8135",
  );
  testSignDetached(
    "e56f0eef73ade8f79bc1d16a99cbc5e4995afd8c14adb49410ecd957aecc8d02",
  );
}
