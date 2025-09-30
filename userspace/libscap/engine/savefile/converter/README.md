# scap converter

The scap converter is a `savefile` engine's component mainly aiming to convert event with old layouts and types to their
latest versions.

Once an event, with a specific type and a specific number of parameters, is read from a scap file, it is checked against
a set of static conversion eligibility rules: these rules allow the converter to determine if the event is eligible for
conversion, if it must be allowed to proceed towards upper layers or must be dropped.

Static conversion eligibility rules are evaluated using a top-down approach. They leverage the following definitions:

- an event having `EF_UNUSED` among its flags is called "unused event"
- an event having `EF_CONVERTER_MANAGED` among its flags is said to be managed by the scap converter
- an event having `EF_OLD_VERSION` among its flags is called an "old event version"

The following is the set of rules:

1. unused events are always dropped
2. events not managed by the converter don't need any conversion; moreover
    1. new event versions are allowed to proceed towards upper layers
    2. old enter event versions are always dropped
    3. (validity check) exit events cannot be old without being managed by the converter
3. enter events always need a conversion
4. old exit event versions, or new exit event versions with a number of expected parameters (as specified in the event
   schema) different from their actual number of parameters, always need a conversion
5. all the other combinations don't need any conversion

Events eligible for conversion are checked against the conversion table defined in `table.cpp`. The conversion table is
indexed by `(event type, event parameters number)` keys, and contains declarative instructions about how to act of a
matching
event. Possible conversion instructions are:

- store the event for later retrieval - used for augmenting exit events with information coming from enter events
- change the event type
- push a new empty parameter (i.e.: a zero-length parameter)
- push a new default parameter (i.e.: the default value associated with the parameter type)
- take a parameter from the corresponding retrieved enter events, if present, or push an empty one as a fallback
- and so on...

After each conversion, the static conversion eligibility rules are always re-checked to determine what do to with the
new event. A static maximum number of conversion prevent the conversion engine to enter an infinite loop of conversions. 