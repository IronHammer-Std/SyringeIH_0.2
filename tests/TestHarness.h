#pragma once
// 最小测试框架（头文件共享版）：
// - 每个测试文件用 TEST_CASE(name) 注册一个用例；
// - main()（RebuildInstructionsTests.cpp）遍历 tests() 统一执行。
#include <cstdio>
#include <vector>

inline int g_total = 0;
inline int g_passed = 0;
inline int g_failed = 0;

struct TestEntry
{
	const char* name;
	void (*fn)();
};

inline std::vector<TestEntry>& tests()
{
	static std::vector<TestEntry> v;
	return v;
}

inline void check_impl(bool cond, const char* expr, const char* file, int line)
{
	++g_total;
	if (cond)
	{
		++g_passed;
	}
	else
	{
		++g_failed;
		printf("  FAIL: %s (%s:%d)\n", expr, file, line);
	}
}

#define CHECK(expr) check_impl(!!(expr), #expr, __FILE__, __LINE__)

#define TEST_CASE(name) \
	static void test_##name(); \
	struct TestReg_##name { TestReg_##name() { tests().push_back({ #name, test_##name }); } } reg_##name; \
	static void test_##name()
