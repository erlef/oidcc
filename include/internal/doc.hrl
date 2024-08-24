%% TODO: Remove the following macros as soon as only OTP >= 27 is supported.
-if(?OTP_RELEASE >= 27).
	-define(MODULEDOC(Str), -moduledoc(Str)).
	-define(DOC(Str), -doc(Str)).
-else.
	-define(MODULEDOC(Str), -compile([])).
	-define(DOC(Str), -compile([])).
-endif.
