package policy

default allow = false

allow {
	input["tee"] == "sample"
}
