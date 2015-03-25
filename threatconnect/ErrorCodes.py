from enum import Enum


class ErrorCodes(Enum):
    e0100 = 'Settings Error: (%s) is an invalid value. Max result counts must be a interger.'
    #
    # Resource Error Codes
    #
    e0500 = 'Resource Error: (%s) is an invalid resource type. Resource types must be a ResourceKey enum.'
    #
    # Filter Error Codes
    #
    e1000 = 'Filter Error: (%s) is an invalid filter operator. Filter Operators must be a FilterSetOperator Enum.'
    # group filters
    e4000 = 'Filter Error: (%s) is an invalid adversary ID. The adversary ID must be an integer.'
    e4005 = 'Filter Error: Adversary filters cannot be used with AdversaryFilterObject.'
    e4010 = 'Filter Error: (%s) is an invalid email ID. The email ID must be an integer.'
    e4015 = 'Filter Error: Email filters cannot be used with EmailFilterObject.'
    e4020 = 'Filter Error: (%s) is an invalid ID. The ID must be an integer.'
    e4030 = 'Filter Error: (%s) is an invalid incident ID. The incident ID must be an integer.'
    e4035 = 'Filter Error: Incident filters cannot be used with IncidentFilterObject.'
    e4040 = 'Filter Error: (%s) is an invalid signature ID. The signature ID must be an integer.'
    e4045 = 'Filter Error: Signature filters cannot be used with SignatureFilterObject.'
    e4050 = 'Filter Error: (%s) is an invalid threat ID. The threat ID must be an integer.'
    e4055 = 'Filter Error: Threat filters cannot be used with ThreatFilterObject.'
    e4060 = 'Filter Error: (%s) is an invalid victim ID. The victim ID must be an integer.'
    e4065 = 'Filter Error: Victim filters cannot be used with VictimFilterObject.'
    e4066 = 'Filter Error: Security Label filters cannot be used with VictimFilterObject.'
    e4067 = 'Filter Error: Tag filters cannot be used with VictimFilterObject.'
    e4070 = 'Filter Error: (%s) is an invalid Security Label. The Security Label must be a string.'
    e4080 = 'Filter Error: (%s) is an invalid Tag. The Tag must be a string.'
    e4090 = 'Filter Error: (%s) is an invalid Hash. The Hash must be a MD5, SHA1, or SHA256.'
    # indicator filters
    e5000 = 'Filter Error: (%s) is an invalid Group ID. The Group ID must be an integer.'
    e5001 = 'Filter Error: (%s) is an invalid Group Type. The Group Type must be a GroupType Enum.'
    e5010 = 'Filter Error: (%s) is an invalid indicator.'
    e5011 = 'Filter Error: (%s) is an invalid indicator type. The Indicator Type must be an GroupType Enum.'
    e5020 = 'Filter Error: (%s) is an invalid Victim ID. The Victim ID must be an integer.'
    e5100 = 'Filter Error: Only one type can be added to a filter. The current filter type is (%s).'
