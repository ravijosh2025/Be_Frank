# frozen_string_literal: true

class Users::SessionsController < Devise::SessionsController
  before_action :authenticate_user!
  def after_sign_in_path_for(resource)
    dashboard_path # Redirects to Dashboard after login
  end
def destroy
    super do
      redirect_to new_user_session_path and return
    end
  end
end
