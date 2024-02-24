// This file contains validation tests for Falco's handling of header field
// syntax. This syntax is loosely based on the dictionary format described in
// RFC-8941.

// Test cases based on fastly's response to the RFC-8941 dictionary tests input
// https://github.com/httpwg/structured-field-tests/blob/main/dictionary.json

sub test_basic_dictionary {
    set req.http.foo = {"en="Applepie", da=:w4ZibGV0w6ZydGUK:"};
    assert.equal(req.http.foo:en, "Applepie");
    // Fastly does not decode binary data fields
    assert.equal(req.http.foo:da, ":w4ZibGV0w6ZydGUK:");
}

sub test_empty_dictionary {
    set req.http.foo = {""};
    assert.is_notset(req.http.foo:a);
}

sub test_single_item_dictionary {
    set req.http.foo = {"a=1"};
    assert.equal(req.http.foo:a, "1");
}

sub test_list_item_dictionary {
    // Fastly does not handle lists correctly, the intuitive expectation for this
    // case would be for the list definition to be returned as a string since VCL
    // does not have sequence types. However the actual returned value is
    // terminated at the first space in the list definition.
    set req.http.foo = {"a=(1 2)"};
    assert.equal(req.http.foo:a, "(1");
}

sub test_single_list_item_dictionary {
    // Single item lists do behave as one would expect them to.
    set req.http.foo = {"a=(1)"};
    assert.equal(req.http.foo:a, "(1)");
}

sub test_no_whitespace_dictionary {
    set req.http.foo = {"a=1,b=2"};
    assert.equal(req.http.foo:a, "1");
    assert.equal(req.http.foo:b, "2");
}

sub test_extra_whitespace_dictionary {
    set req.http.foo = {"a=1 ,  b=2"};
    assert.equal(req.http.foo:a, "1");
    assert.equal(req.http.foo:b, "2");
}

sub test_tab_separated_dictionary {
    set req.http.foo = {"a=1	,	b=2"};
    assert.equal(req.http.foo:a, "1");
    assert.equal(req.http.foo:b, "2");
}

sub test_leading_whitespace_dictionary {
    set req.http.foo = {"     a=1 ,  b=2"};
    assert.equal(req.http.foo:a, "1");
    assert.equal(req.http.foo:b, "2");
}

sub test_whitespace_before_equal_dictionary {
    // RFC says this should be an error. Fastly simply ignores the whitespace.
    set req.http.foo = "a =1, b=2";
    assert.equal(req.http.foo:a, "1");
    assert.equal(req.http.foo:b, "2");
}

sub test_whitespace_after_equal_dictionary {
    // RFC says this should be an error. Fastly simply ignores the whitespace.
    set req.http.foo = "a=1, b= 2";
    assert.equal(req.http.foo:a, "1");
    assert.equal(req.http.foo:b, "2");
}

sub test_two_lines_dictionary {
    // Fastly truncates header values at newlines so the b value will be missing.
    set req.http.foo = "a=1" LF "b=2";
    assert.equal(req.http.foo, "a=1");
    assert.equal(req.http.foo:a, "1");
    assert.is_notset(req.http.foo:b);
}

sub test_missing_value_dictionary {
    set req.http.foo = "a=1, b, c=3";
    assert.equal(req.http.foo:a, "1");
    assert.equal(req.http.foo:b, "");
    assert.equal(req.http.foo:c, "3");
}

sub test_all_missing_value_dictionary {
    set req.http.foo = "a, b, c";
    assert.equal(req.http.foo:a, "");
    assert.equal(req.http.foo:b, "");
    assert.equal(req.http.foo:c, "");
}

sub test_start_missing_value_dictionary {
    set req.http.foo = "a, b=2";
    assert.equal(req.http.foo:a, "");
    assert.equal(req.http.foo:b, "2");
}

sub test_end_missing_value_dictionary {
    set req.http.foo = "a=1, b";
    assert.equal(req.http.foo:a, "1");
    assert.equal(req.http.foo:b, "");
}

sub test_missing_value_with_params_dictionary {
    set req.http.foo = "a=1, b;foo=9, c=3";
    assert.equal(req.http.foo:a, "1");
    assert.is_notset(req.http.foo:b);
    assert.equal(req.http.foo:c, "3");
}

sub test_explicit_true_value_with_params_dictionary {
    set req.http.foo = "a=1, b=?1;foo=9, c=3";
    assert.equal(req.http.foo:a, "1");
    assert.equal(req.http.foo:b, "?1;foo=9");
    assert.equal(req.http.foo:c, "3");
}

sub test_trailing_comma_dictionary {
    // RFC says this should be an error. Fastly ignores the trailing comma.
    set req.http.foo = "a=1, b=2,";
    assert.equal(req.http.foo:a, "1");
    assert.equal(req.http.foo:b, "2");
}

sub test_empty_item_dictionary {
    // RFC says this should be an error. Fastly ignores the empty item.
    set req.http.foo = "a=1,,b=2,";
    assert.equal(req.http.foo:a, "1");
    assert.equal(req.http.foo:b, "2");
}

sub test_duplicate_key_dictionary {
    set req.http.foo = "a=1,b=2,a=3";
    assert.equal(req.http.foo:a, "1");
    assert.equal(req.http.foo:b, "2");
}

sub test_numeric_key_dictionary {
    // RFC says this should be an error. Fastly treats it as a valid key.
    set req.http.foo = "a=1,1b=2,a=1";
    assert.equal(req.http.foo:a, "1");
    assert.equal(req.http.foo:1b, "2");
}

sub test_uppercase_key_dictionary {
    // RFC says this should be an error. Fastly treats keys as case-insensitive.
    set req.http.foo = "a=1,B=2,a=1";
    assert.equal(req.http.foo:a, "1");
    assert.equal(req.http.foo:B, "2");
    assert.equal(req.http.foo:b, "2");
}

sub test_bad_key_dictionary {
    // RFC says this should be an error. Fastly ignores the bad key.
    set req.http.foo = "a=1,b!=2,a=1";
    assert.equal(req.http.foo:a, "1");
    assert.is_notset(req.http.foo:b);
}

// Additional tests of basic functionality and edge cases found through
// experimentation.

sub test_set_new_field {
    set req.http.foo = {"a=1"};
    set req.http.foo:b = "2";
    assert.equal(req.http.foo, "a=1,b=2");
    assert.equal(req.http.foo:a, "1");
    assert.equal(req.http.foo:b, "2");
}

sub test_set_existing_field {
    set req.http.foo = {"a=1,b=3"};
    set req.http.foo:a = "2";
    assert.equal(req.http.foo, "b=3,a=2");
    assert.equal(req.http.foo:a, "2");
    assert.equal(req.http.foo:b, "3");
}

sub test_set_unset_header_unset_value {
    set req.http.foo:a = req.http.unset;
    set req.http.foo:ab = req.http.unset;
    assert.equal(req.http.foo, "ab");
    assert.is_notset(req.http.foo:a);
    assert.equal(req.http.foo:ab, "");
}

sub test_set_empty_header_unset_value {
    set req.http.foo = "";
    set req.http.foo:a = req.http.unset;
    set req.http.foo:ab = req.http.unset;
    assert.equal(req.http.foo, "ab");
    assert.is_notset(req.http.foo:a);
    assert.equal(req.http.foo:ab, "");
}

sub test_set_nonempty_header_unset_value {
    set req.http.foo = "c=1";
    set req.http.foo:a = req.http.unset;
    set req.http.foo:ab = req.http.unset;
    assert.equal(req.http.foo, "c=1,a,ab");
    assert.equal(req.http.foo:c, "1");
    assert.equal(req.http.foo:a, "");
    assert.equal(req.http.foo:ab, "");
}

sub test_set_value_with_leading_whitespace {
    set req.http.foo:space = " asdf asdf ";
    assert.equal(req.http.foo, {"space=" asdf asdf ""});
    assert.equal(req.http.foo:space, " asdf asdf ");
}

sub test_value_with_comma {
    set req.http.foo = {"a=1,b="a,d=asdf",e=asdf"};
    assert.equal(req.http.foo:a, "1");
    assert.equal(req.http.foo:d, {"asdf""});
    assert.equal(req.http.foo:e, "asdf");
    assert.equal(req.http.foo:b, "a,d=asdf");
}

sub test_set_value_with_comma {
    set req.http.foo = {"a=1,e=asdf"};
    set req.http.foo:b = "2,c=3";
    assert.equal(req.http.foo:a, "1");
    assert.equal(req.http.foo:c, {"3""});
    assert.equal(req.http.foo:e, "asdf");
    assert.equal(req.http.foo:b, "2,c=3");
}

sub test_unset_first_dictionary_entry {
    set req.http.foo = "abc=1,def=2,ghi=3";
    unset req.http.foo:abc;
    assert.equal(req.http.foo, "def=2,ghi=3");
}

sub test_unset_middle_dictionary_entry {
    set req.http.foo = "abc=1,def=2,ghi=3";
    unset req.http.foo:def;
    assert.equal(req.http.foo, "abc=1,ghi=3");
}

sub test_unset_last_dictionary_entry {
    set req.http.foo = "abc=1,def=2,ghi=3";
    unset req.http.foo:ghi;
    assert.equal(req.http.foo, "abc=1,def=2");
}

sub test_backslash_does_not_escape_comma {
    set req.http.comma = {"a=c\,adf,b=asdf"};
    assert.equal(req.http.comma:a, {"c\"});
    assert.is_notset(req.http.comma:c);
    assert.equal(req.http.comma:adf, "");
    assert.equal(req.http.comma:b, "asdf");
}

sub test_unset_last_field {
    set req.http.foo = "a=1";
    unset req.http.foo:a;
    assert.is_notset(req.http.foo);
}

sub test_set_header_field_with_newline {
    set req.http.foo:a = "1" LF "2";
    assert.equal(req.http.foo, {"a="1"});
    assert.equal(req.http.foo:a, "1");
}

sub test_set_uppercase_key {
    set req.http.foo:A = "1";
    assert.equal(req.http.foo, "A=1");
}

sub test_set_swapped_case_key {
    set req.http.foo:A = "1";
    set req.http.foo:a = "2";
    assert.equal(req.http.foo, "a=2");
}

sub test_special_character_quotes {
    // = @ ( ) [ ] { } ? / \\ ; : ' < > ,
    set req.http.foo:a = " ";
    assert.equal(req.http.foo, {"a=" ""});
    set req.http.foo:a = "	";
    assert.equal(req.http.foo, {"a="	""});
    set req.http.foo:a = "=";
    assert.equal(req.http.foo, {"a="=""});
    set req.http.foo:a = "@";
    assert.equal(req.http.foo, {"a="@""});
    set req.http.foo:a = "(";
    assert.equal(req.http.foo, {"a="(""});
    set req.http.foo:a = ")";
    assert.equal(req.http.foo, {"a=")""});
    set req.http.foo:a = "[";
    assert.equal(req.http.foo, {"a="[""});
    set req.http.foo:a = "]";
    assert.equal(req.http.foo, {"a="]""});
    set req.http.foo:a = "{";
    assert.equal(req.http.foo, {"a="{""});
    set req.http.foo:a = "}";
    assert.equal(req.http.foo, {"a=""} "}" {"""});
    set req.http.foo:a = "?";
    assert.equal(req.http.foo, {"a="?""});
    set req.http.foo:a = "/";
    assert.equal(req.http.foo, {"a="/""});
    set req.http.foo:a = "\";
    assert.equal(req.http.foo, {"a="\""});
    set req.http.foo:a = ";";
    assert.equal(req.http.foo, {"a=";""});
    set req.http.foo:a = ":";
    assert.equal(req.http.foo, {"a=":""});
    set req.http.foo:a = "'";
    assert.equal(req.http.foo, {"a="'""});
    set req.http.foo:a = "<";
    assert.equal(req.http.foo, {"a="<""});
    set req.http.foo:a = ">";
    assert.equal(req.http.foo, {"a=">""});
    set req.http.foo:a = ",";
    assert.equal(req.http.foo, {"a=",""});
}