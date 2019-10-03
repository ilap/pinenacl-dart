part of pinenacl.api;

typedef Constructor<T> = T Function();

Map<String, Constructor<Object>> _constructors = <String, Constructor<Object>>{
  'Curve25519': () => Curve25519(),
  'Ed25519': () => Ed25519()
};

class Registrar {
  static void register<T>(Constructor<T> constructor) {
    _constructors[T.toString()] = constructor;
  }

  static dynamic getInstance(String type) {
    // TODO:  it returns an Ed25519 instance,
    // or threw an Exception
    return (_constructors[type] ?? _constructors['Ed25519'])();
  }
}
