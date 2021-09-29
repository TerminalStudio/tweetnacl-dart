import 'package:tweetnacl2/tweetnacl2.dart';
import "dart:convert";

void testSignDetached(String seedStr) {
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

  assert(result == true);
}

void main() {
  testSignDetached(
    "ac49000da11249ea3510941703a7e21a39837c4d2d5300daebbd532df20f8135",
  );
  testSignDetached(
    "e56f0eef73ade8f79bc1d16a99cbc5e4995afd8c14adb49410ecd957aecc8d02",
  );
}
