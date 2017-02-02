This README describes how to reproduce and verify the conformance test
results of oidcc as an RP.

# Getting the Source
The following lines clone the git repository, there is no need to checkout a certain version
of the library as the versions are configured in 'oidcc/conformance/rebar.conf'.
```
git clone https://github.com/indigo-dc/oidcc.git
cd oidcc
```

# Running the tests
It will create the directory '/tmp/oidcc_rp_conformance' and put the logs
of oidcc and of the openid.net test-server in the sub directories according
to the profile.

## Running manually
The following lines will start the oidcc test-server and provide links to you
for each test
```
cd conformance
make run
```
Now point the browser to the [oidcc test server](https://localhost:8080). By selecting
a link a test will be started and the logs created and the progress can be watched in the
terminal.

## Running in Batch Mode
The following lines will run all tests in batch.
```
cd conformance
make conformance_test
```


# Verifying the Results
Each test is saved in its own '*.log' file called after its official test name.
All logfiles start with the name and start date, like
  'starting test <<"rp-response_type-code">> at <<"Mon, 30 Jan 2017 07:35:08 GMT">>'
The unusual output of the testname, surrounded by << and >> is caused by the
programming language (it is Erlang, using binary).

Every time a dynamic registration is started and the result shown in the log.
After registration an authentication request is triggered, and its result is shown as
one of the two lines
 - User logged in ....
 - User not logged in ....
On succesful login the decoded and validated token information is shown, if an error
occured the reason is logged.
The last line logs what the author thinks the logged information results in - either
passed or failed.

## In depth checks
The differentiation between passing and failing is done in the file
  'oidcc/conformance/src/conformance.erl'.

Each test has a two functions being called:
- test_<test_name>: starting the test (might be shared between mutliple tests)
- check_<test_name>: validating the result
All functions are documented with their desired behaviour. If the check_* function
returns 'true' the test is marked as passed.
