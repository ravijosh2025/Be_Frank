require "test_helper"

class UserDonationsControllerTest < ActionDispatch::IntegrationTest
  test "should get index" do
    get user_donations_index_url
    assert_response :success
  end
end
