class HomeController < ApplicationController
  def redirect_to_login
    redirect_to new_user_session_path
  end
end
