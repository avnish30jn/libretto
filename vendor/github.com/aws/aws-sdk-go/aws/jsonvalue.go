package aws

// JSONValue is a representation of a grab bag type that will be marshaled
// into a json string. This type can be used just like any other map.
//
//	Example:
<<<<<<< HEAD
<<<<<<< HEAD
//
//	values := aws.JSONValue{
=======
//	values := JSONValue{
>>>>>>> Revendor using dep tool
=======
//
//	values := aws.JSONValue{
>>>>>>> Update all deps
//		"Foo": "Bar",
//	}
//	values["Baz"] = "Qux"
type JSONValue map[string]interface{}
