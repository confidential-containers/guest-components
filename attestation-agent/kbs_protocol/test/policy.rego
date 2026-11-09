package policy

default allow = false

allow if {
	data.plugin == "resource"
	input["submods"]["cpu0"]["ear_attester_claims"]["tee"] == "sample"
}
