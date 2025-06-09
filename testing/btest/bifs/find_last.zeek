#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	local s = "this is a test string with multiple patterns";
	
	# Test 1: Basic pattern matching
	local pat1 = /hi|es/;
	print "Test 1 - Basic pattern:";
	print find_last(s, pat1);  # Should find "es" as it's the last match
	print "-------------------";

	# Test 2: Pattern not found
	local pat2 = /aa|bb/;
	print "Test 2 - No match:";
	print |find_last(s, pat2)|;
	print "-------------------";

	# Test 3: Find with offset before pattern
	local pat3 = /is/;
	print "Test 3 - Offset before pattern:";
	print find_last(s, pat3, 0);  # Should not find, offset before first "is"
	print find_last(s, pat3, 5);  # Should find first "is"
	print find_last(s, pat3, 10); # Should find second "is"
	print "-------------------";

	# Test 4: Find with offset at pattern
	local pat4 = /test/;
	print "Test 4 - Offset at pattern:";
	print find_last(s, pat4, 10);  # Should find "test"
	print find_last(s, pat4, 9);   # Should not find, offset before "test"
	print "-------------------";

	# Test 5: Find with offset after pattern
	local pat5 = /with/;
	print "Test 5 - Offset after pattern:";
	print find_last(s, pat5, 30);  # Should find "with"
	print find_last(s, pat5, 10);  # Should not find, offset before "with"
	print "-------------------";

	# Test 6: Find with offset beyond string length
	print "Test 6 - Offset beyond length:";
	print find_last(s, pat1, 100);  # Should find last match "es"
	print "-------------------";

	# Test 7: Find with offset at end of string
	print "Test 7 - Offset at end:";
	print find_last(s, pat1, |s|-1);  # Should find last match "es"
	print "-------------------";

	# Test 8: Find with multiple patterns and offsets
	local pat8 = /is|test|with/;
	print "Test 8 - Multiple patterns:";
	print find_last(s, pat8, 0);   # Should not find, offset before first match
	print find_last(s, pat8, 5);   # Should find first "is"
	print find_last(s, pat8, 10);  # Should find second "is"
	print find_last(s, pat8, 20);  # Should find "test"
	print find_last(s, pat8, 30);  # Should find "with"
	print "-------------------";

	# Test 9: Find with empty string
	print "Test 9 - Empty string:";
	print |find_last("", pat1)|;  # Should return empty string
	print "-------------------";

	# Test 10: Find with pattern matching start of string
	local pat10 = /^/;  # Pattern matching start of string
	print "Test 10 - Start of string pattern:";
	print find_last(s, pat10);  # Should find start of string
	print "-------------------";

	# Test 11: Find with overlapping patterns
	local s2 = "aaaa";
	local pat11 = /aa/;
	print "Test 11 - Overlapping patterns:";
	print find_last(s2, pat11);  # Should find last "aa"
	print find_last(s2, pat11, 2);  # Should find first "aa"
	print "-------------------";
	}
