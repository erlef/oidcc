-module(oidcc_token_test).
-include_lib("eunit/include/eunit.hrl").


extract_test() ->
    RawData =
    <<"{\"access_token\":\"fimr6kVbXlCueoTDvHIofHAaGDeE7DM8\",\"expires_in\":600,\"id_token\":\"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE0NjA5NjI0NzUsImlzcyI6Imh0dHBzOi8vcHJvdG9uLnNjYy5raXQuZWR1Iiwic3ViIjoiam9lIiwiYXVkIjoiMTIzIiwiaWF0IjoxNDYwOTYyMTc0LCJhdXRoX3RpbWUiOjE0NjA5NjIxNzR9.bJUAXVktgAAIIlw6fshlF035NfpNJ4aF8VfoIt4Kf5UyfTBzG1m9AGClvEFWieWnSJ6AxAV5dLJd3L-_tPs3cM9qUxssuY5CoKtc659X0B8cAOR4vK3ImyEAnipnUGYXcP3Ju8vkqtP75_GOUnbWEtNtxT-GK_2ysRQyF6wpRQHL-lj5u-lhZBHXDDJmGB5A4pex_zdtemlPFc9Ij_XDbmMEh-BoT9r9orC7prJ-ih3cGz3YKfOyxYQO8VPueucwouFcR8FCKasN3IOgyPfUnJl5wtsbm54u94dgu_uMpaIOeDnWbyEUsFldUvhGVJKlXlsk3Q34sFR-0FT1IOvCke\",\"refresh_token\":\"Aw2FafLPDAeysVkPPiQUkOdhtBPpXyNS\",\"token_type\":\"Bearer\"}">>,
    ExpectedOutput = #{access => #{expires => 600,token => <<"fimr6kVbXlCueoTDvHIofHAaGDeE7DM8">>, hash => undefined},
                       refresh => #{ token => <<"Aw2FafLPDAeysVkPPiQUkOdhtBPpXyNS">>},
                        id => #{token => <<"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE0NjA5NjI0NzUsImlzcyI6Imh0dHBzOi8vcHJvdG9uLnNjYy5raXQuZWR1Iiwic3ViIjoiam9lIiwiYXVkIjoiMTIzIiwiaWF0IjoxNDYwOTYyMTc0LCJhdXRoX3RpbWUiOjE0NjA5NjIxNzR9.bJUAXVktgAAIIlw6fshlF035NfpNJ4aF8VfoIt4Kf5UyfTBzG1m9AGClvEFWieWnSJ6AxAV5dLJd3L-_tPs3cM9qUxssuY5CoKtc659X0B8cAOR4vK3ImyEAnipnUGYXcP3Ju8vkqtP75_GOUnbWEtNtxT-GK_2ysRQyF6wpRQHL-lj5u-lhZBHXDDJmGB5A4pex_zdtemlPFc9Ij_XDbmMEh-BoT9r9orC7prJ-ih3cGz3YKfOyxYQO8VPueucwouFcR8FCKasN3IOgyPfUnJl5wtsbm54u94dgu_uMpaIOeDnWbyEUsFldUvhGVJKlXlsk3Q34sFR-0FT1IOvCke">>
                      , claims => undefined}},
    ExpectedOutput = oidcc_token:extract_token_map(RawData),
    ok.


-define(RSA_PUBLIC_KEY,[65537, 26764034142824704671470727133910664843434961952272064166426226039805773031712563508339384620585192869091085197093344386232207542619708787421377966896296841271368128705832667137731759368836398793992412062213039259549646668413294499661784015754202306959856976300366659103241590400757099670805804654764282426982148086034348017908262389651476327142185608358813461989019448157613779262598416478574844583047253739496922447827706849259886451307152776609476861777213322863455948194927465841543344937499194416674011076061250124513400818349182398008202094247204740240584520318269147256825860139612842332966614539793342302993867]).

-define(RSA_PRIVATE_KEY,{'RSAPrivateKey','two-prime',
                     26764034142824704671470727133910664843434961952272064166426226039805773031712563508339384620585192869091085197093344386232207542619708787421377966896296841271368128705832667137731759368836398793992412062213039259549646668413294499661784015754202306959856976300366659103241590400757099670805804654764282426982148086034348017908262389651476327142185608358813461989019448157613779262598416478574844583047253739496922447827706849259886451307152776609476861777213322863455948194927465841543344937499194416674011076061250124513400818349182398008202094247204740240584520318269147256825860139612842332966614539793342302993867,
                     65537,
                     12794561693313670100205653006781224797363586340001583385478945661643268216176428806876618096082122962427692741885262975428461209855127276346365743059050308024962440641984489088989975449374313353003376259351732914257448923835215476363026888834996387949590598707455138772060958348043394306824326103327356583873848688304161573971837684253713093328415056019518486753353685104889273063916897235433180509399999298673446273215515841603080826297295537431001587831668670650206107678796371102894820869947413565783400511327660856890784768064128415588379491565702377411884622967328023716684228979596814867941892555080877039934913,
                     175921812047663448018479509235149059234162469604896431741565550421215807198867689136961832929735756392012649052466171066035877581304404480112067613119039884401516991962137582818872105841975489123820547558891955007907269296649095288060806030752931271323412548318651305799213788576544135388323426837173991918523,
                     152135962171497984267966543913856108347630812566910071974963337510843417419284055362416709755317088206676526904022621662056506919405421710738842624864481880983646685082220280096388715674338529824473346539992718562264652001183670660912857359719070110573506895077317198382716742487416742094479674005148886682929,
                     7940197446282076983057851111853928577973550591136055130560613060499509554820187443232572467555096623397064496348550193224195887597821512308642385211500678670974979968933624822287008698606336830008410206130924560376424044119932616111263320551248465760938924850490113410044316746409166615479205587444659781421,
                     84323951750609034263605058328437724273733757518546902734188980805978106073752129499973861816407422205891707581802977430675841339203838192816095615426435514697513859890011011710962053448744176509055866351301333624887673893266350866802867747864492145911204937114661141511698516423629600936600304533882132364273,
                     146498358518282536624753849370270691372323087909948725666061752883743908775492534384951112165832037025133690750650675527600809535328134914630670173454194925358833883485231412349407499865536427735554260391108738360645045140719276539512627330123338501657698608899096243687786198062042440767530650052735017635902,
                     asn1_NOVALUE}).

validate_pass_test() ->
    Nonce = <<"some random noce">>,
    ClientId = <<"234234211">>,
    OpenIdProviderId = <<"MyMockedProvider">>,
    Issuer = <<"https://mocked.provider">>,
    mock_oidcc(OpenIdProviderId,Issuer, ClientId),

    IdToken = generate_id_token(valid,ClientId,Nonce,Issuer),
    {ok,#{}} = oidcc_token:validate_id_token(IdToken, OpenIdProviderId, Nonce),
    stop_mocking_oidcc(),
    ok.


validate_group_pass_test() ->
    Nonce = <<"some random noce">>,
    ClientId = <<"234234211">>,
    OpenIdProviderId = <<"MyMockedProvider">>,
    Issuer = <<"https://mocked.provider">>,
    mock_oidcc(OpenIdProviderId,Issuer, ClientId),

    IdToken = generate_id_token(valid_group,ClientId,Nonce,Issuer),
    {ok,#{}} = oidcc_token:validate_id_token(IdToken, OpenIdProviderId, Nonce),
    stop_mocking_oidcc(),
    ok.


validate_fail_field_test() ->
    Nonce = <<"some noce">>,
    ClientId = <<"23423211">>,
    OpenIdProviderId = <<"MyMockedProvider">>,
    Issuer = <<"https://mocked.provider">>,
    mock_oidcc(OpenIdProviderId,Issuer, ClientId),

    IdToken = generate_id_token(missing_field,ClientId,Nonce,Issuer),
    {error, {required_fields_missing, _}} = oidcc_token:validate_id_token(IdToken, OpenIdProviderId, Nonce),
    stop_mocking_oidcc(),
    ok.


validate_fail_issuer_test() ->
    Nonce = <<"some noce">>,
    ClientId = <<"23423211">>,
    OpenIdProviderId = <<"MyMockedProvider">>,
    Issuer = <<"https://mocked.provider">>,
    BadIssuer = <<"https://bad.provider">>,
    mock_oidcc(OpenIdProviderId,Issuer, ClientId),

    IdToken = generate_id_token(valid,ClientId,Nonce,BadIssuer),
    {error, {wrong_issuer, BadIssuer, Issuer}} = oidcc_token:validate_id_token(IdToken, OpenIdProviderId, Nonce),
    stop_mocking_oidcc(),
    ok.

validate_fail_audience_test() ->
    Nonce = <<"some noce">>,
    ClientId = <<"23423211">>,
    BadClientId = <<"2342311">>,
    OpenIdProviderId = <<"MyMockedProvider">>,
    Issuer = <<"https://mocked.provider">>,
    mock_oidcc(OpenIdProviderId,Issuer, ClientId),

    IdToken = generate_id_token(valid,BadClientId,Nonce,Issuer),
    {error, not_in_audience} = oidcc_token:validate_id_token(IdToken, OpenIdProviderId, Nonce),
    stop_mocking_oidcc(),
    ok.

validate_fail_audience_group_test() ->
    Nonce = <<"some noce">>,
    ClientId = <<"23423211">>,
    BadClientId = <<"2342311">>,
    OpenIdProviderId = <<"MyMockedProvider">>,
    Issuer = <<"https://mocked.provider">>,
    mock_oidcc(OpenIdProviderId,Issuer, ClientId),

    IdToken = generate_id_token(valid_group,BadClientId,Nonce,Issuer),
    {error, not_in_audience} = oidcc_token:validate_id_token(IdToken, OpenIdProviderId, Nonce),
    stop_mocking_oidcc(),
    ok.

validate_fail_algo_test() ->
    Nonce = <<"some noce">>,
    ClientId = <<"23423211">>,
    OpenIdProviderId = <<"MyMockedProvider">>,
    Issuer = <<"https://mocked.provider">>,
    mock_oidcc(OpenIdProviderId,Issuer, ClientId),

    IdToken = generate_id_token(bad_algo,ClientId,Nonce,Issuer),
    {error, bad_algorithm} = oidcc_token:validate_id_token(IdToken, OpenIdProviderId, Nonce),
    stop_mocking_oidcc(),
    ok.

validate_fail_expired_test() ->
    Nonce = <<"some noce">>,
    ClientId = <<"23423211">>,
    OpenIdProviderId = <<"MyMockedProvider">>,
    Issuer = <<"https://mocked.provider">>,
    mock_oidcc(OpenIdProviderId,Issuer, ClientId),

    IdToken = generate_id_token(expired,ClientId,Nonce,Issuer),
    {error, expired} = oidcc_token:validate_id_token(IdToken, OpenIdProviderId, Nonce),
    stop_mocking_oidcc(),
    ok.


validate_fail_nonce_test() ->
    Nonce = <<"some noce">>,
    BadNonce = <<"some bad noce">>,
    ClientId = <<"23423211">>,
    OpenIdProviderId = <<"MyMockedProvider">>,
    Issuer = <<"https://mocked.provider">>,
    mock_oidcc(OpenIdProviderId,Issuer, ClientId),

    IdToken = generate_id_token(valid,ClientId,BadNonce,Issuer),
    {error, wrong_nonce} = oidcc_token:validate_id_token(IdToken, OpenIdProviderId, Nonce),
    stop_mocking_oidcc(),
    ok.

generate_id_token(missing_field,ClientId,Nonce,Issuer) ->
    ClaimSetMap = #{iss => Issuer,
                    aud => [ClientId, <<"someotherid">>],
                    nonce => Nonce,
                    sub => <<"joe">>
                   },
    generate_id_token(ClaimSetMap,600);
generate_id_token(valid_group,ClientId,Nonce,Issuer) ->
    ClaimSetMap = #{iss => Issuer,
                    aud => [ClientId, <<"someotherid">>],
                    azp => ClientId,
                    nonce => Nonce,
                    sub => <<"joe">>,
                    iat => 123
                   },
    generate_id_token(ClaimSetMap,600);
generate_id_token(valid,ClientId,Nonce,Issuer) ->
    ClaimSetMap = #{iss => Issuer,
                    aud => ClientId,
                    nonce => Nonce,
                    sub => <<"joe">>,
                    iat => 123
                   },
    generate_id_token(ClaimSetMap,600);
generate_id_token(expired,ClientId,Nonce,Issuer) ->
    ClaimSetMap = #{iss => Issuer,
                    aud => ClientId,
                    nonce => Nonce,
                    sub => <<"joe">>,
                    iat => 123
                   },
    generate_id_token(ClaimSetMap,-600);
generate_id_token(bad_algo,ClientId,Nonce,Issuer) ->
    ClaimSetMap = #{iss => Issuer,
                    aud => ClientId,
                    nonce => Nonce,
                    sub => <<"joe">>,
                    iat => 123
                   },
    Key = <<"some shared secret">>,
    erljwt:jwt(hs256,ClaimSetMap,600,Key).



mock_oidcc(OpenIdProviderId, Issuer, ClientId) ->
     InfoFun = fun(Id) ->
                       Id = OpenIdProviderId,
                       {ok, #{issuer => Issuer,
                         client_id => ClientId,
                         keys => [#{ kty => rsa, key => ?RSA_PUBLIC_KEY,
                                     use => sign}]
                        }}
               end,
    ok = meck:new(oidcc),
    ok = meck:expect(oidcc, get_openid_provider_info, InfoFun),

    ok.

stop_mocking_oidcc() ->
    true = meck:validate(oidcc),
    meck:unload(oidcc),
    ok.

generate_id_token(ClaimSetMap,Expiration) ->
    erljwt:jwt(rs256,ClaimSetMap,Expiration,?RSA_PRIVATE_KEY).
