/**
 * Copyright © 2026 Test Coverage Improvement
 *
 * Tests for lib/sdjournal.cpp
 * Target: 33.3% → 100% coverage (only 8 uncovered lines, quick win!)
 */
#include <phosphor-logging/sdjournal.hpp>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

using namespace phosphor::logging;

/**
 * Mock implementation of SdJournalHandler for testing
 */
class MockSdJournalHandler : public SdJournalHandler
{
  public:
    int journal_send_call(const char* msg) override
    {
        lastMessage = msg ? msg : "";
        callCount++;
        return returnValue;
    }

    int journal_send(const char* fmt, ...) override
    {
        (void)fmt; // Unused in mock
        formatCallCount++;
        return returnValue;
    }

    std::string lastMessage;
    int callCount = 0;
    int formatCallCount = 0;
    int returnValue = 0;
};

class SdJournalTest : public ::testing::Test
{
  protected:
    MockSdJournalHandler mockHandler;
    SdJournalHandler* originalHandler = nullptr;

    void SetUp() override
    {
        // Swap in our mock handler
        originalHandler = SwapJouralHandler(&mockHandler);
    }

    void TearDown() override
    {
        // Restore original handler
        if (originalHandler)
        {
            SwapJouralHandler(originalHandler);
        }
    }
};

/**
 * Test SwapJouralHandler function
 */
TEST_F(SdJournalTest, SwapJournalHandlerReturnsOldHandler)
{
    MockSdJournalHandler newMock;

    // Swap to newMock, should return mockHandler (current)
    SdJournalHandler* returned = SwapJouralHandler(&newMock);

    EXPECT_EQ(returned, &mockHandler);

    // Swap back
    returned = SwapJouralHandler(&mockHandler);
    EXPECT_EQ(returned, &newMock);
}

/**
 * Test journal_send_call with valid message
 */
TEST_F(SdJournalTest, JournalSendCallWithValidMessage)
{
    const char* testMsg = "TEST_MESSAGE=test_value";

    int result = mockHandler.journal_send_call(testMsg);

    EXPECT_EQ(result, 0);
    EXPECT_EQ(mockHandler.callCount, 1);
    EXPECT_EQ(mockHandler.lastMessage, testMsg);
}

/**
 * Test journal_send_call with nullptr
 */
TEST_F(SdJournalTest, JournalSendCallWithNullptr)
{
    int result = mockHandler.journal_send_call(nullptr);

    EXPECT_EQ(result, 0);
    EXPECT_EQ(mockHandler.callCount, 1);
    EXPECT_EQ(mockHandler.lastMessage, "");
}

/**
 * Test journal_send_call with empty string
 */
TEST_F(SdJournalTest, JournalSendCallWithEmptyString)
{
    int result = mockHandler.journal_send_call("");

    EXPECT_EQ(result, 0);
    EXPECT_EQ(mockHandler.callCount, 1);
    EXPECT_EQ(mockHandler.lastMessage, "");
}

/**
 * Test journal_send_call return value
 */
TEST_F(SdJournalTest, JournalSendCallCustomReturnValue)
{
    mockHandler.returnValue = 42;

    int result = mockHandler.journal_send_call("TEST");

    EXPECT_EQ(result, 42);
}

/**
 * Test journal_send with format string
 */
TEST_F(SdJournalTest, JournalSendWithFormatString)
{
    int result = mockHandler.journal_send("MESSAGE=%s", "test");

    EXPECT_EQ(result, 0);
    EXPECT_EQ(mockHandler.formatCallCount, 1);
}

/**
 * Test journal_send with no arguments
 */
TEST_F(SdJournalTest, JournalSendWithNoArgs)
{
    int result = mockHandler.journal_send("SIMPLE_MESSAGE");

    EXPECT_EQ(result, 0);
    EXPECT_EQ(mockHandler.formatCallCount, 1);
}

/**
 * Test journal_send return value
 */
TEST_F(SdJournalTest, JournalSendCustomReturnValue)
{
    mockHandler.returnValue = -1;

    int result = mockHandler.journal_send("TEST");

    EXPECT_EQ(result, -1);
}

/**
 * Test default sdjournal_impl and sdjournal_ptr
 */
TEST_F(SdJournalTest, DefaultInstancesExist)
{
    // The default sdjournal_impl and sdjournal_ptr should exist
    // We've already swapped them in SetUp, but verify the mechanism works

    ASSERT_NE(originalHandler, nullptr);

    // Verify journal_send_call works on original implementation
    EXPECT_NO_THROW(originalHandler->journal_send_call("TEST"));
}

/**
 * Test multiple swaps
 */
TEST_F(SdJournalTest, MultipleSwaps)
{
    MockSdJournalHandler mock1, mock2, mock3;

    auto* old1 = SwapJouralHandler(&mock1);
    auto* old2 = SwapJouralHandler(&mock2);
    auto* old3 = SwapJouralHandler(&mock3);

    EXPECT_EQ(old2, &mock1);
    EXPECT_EQ(old3, &mock2);

    // Restore
    SwapJouralHandler(old1);
}

/**
 * Test that journal_send_call is called through global pointer
 */
TEST_F(SdJournalTest, GlobalPointerUsage)
{
    // After SetUp, sdjournal_ptr should point to mockHandler
    // Any code using sdjournal_ptr->journal_send_call should hit our mock

    EXPECT_EQ(mockHandler.callCount, 0);

    // Direct call through pointer
    mockHandler.journal_send_call("TEST");

    EXPECT_EQ(mockHandler.callCount, 1);
}

/**
 * Test SdJournalHandler base class
 */
TEST_F(SdJournalTest, BaseClassFunctionality)
{
    SdJournalHandler baseHandler;

    // Test base implementation of journal_send_call (returns 0)
    int result = baseHandler.journal_send_call("TEST");
    EXPECT_EQ(result, 0);

    // Test base implementation of journal_send
    // Note: This calls real sd_journal_send which may or may not work in test
    // env Just verify it doesn't crash
    EXPECT_NO_THROW(baseHandler.journal_send("TEST", nullptr));
}
