# frozen_string_literal: true
class Users::RegistrationsController < Devise::RegistrationsController
  respond_to :json

  protected

  def after_sign_up_path_for(resource)
    new_user_session_path # Redirects to /users/sign_in
  end
end
