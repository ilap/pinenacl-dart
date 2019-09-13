import 'box_test.dart' as box_test;
import 'secretbox_test.dart' as secretbox_test;
import 'diffie_hellman_test.dart' as dh_test;
import 'hashing_test.dart' as hashing_test;
import 'signing_test.dart' as signing_test;

void main() {
  box_test.main();
  secretbox_test.main();
  hashing_test.main();
  signing_test.main();
  dh_test.main();
}
