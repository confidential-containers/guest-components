package policy

default allow = false

allow if {
	input["submods"]["cpu0"]["ear.veraison.annotated-evidence"]["sample"]
}
