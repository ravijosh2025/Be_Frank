class ApplicationController < ActionController::Base
  include Auth
  # Only allow modern browsers supporting webp images, web push, badges, import maps, CSS nesting, and CSS :has.
  allow_browser versions: :modern
  protect_from_forgery with: :exception, unless: -> { request.format.json? } # CSRF for web only
  skip_before_action :verify_authenticity_token, unless: -> { request.format.json? }
  before_action :authenticate_request
  skip_before_action :authenticate_request, if: :devise_controller?
  before_action :configure_sign_up_params, if: :devise_controller?

  private

  # If you have extra params to permit, append them to the sanitizer.
  def configure_sign_up_params
    devise_parameter_sanitizer.permit(:sign_up, keys: [ :first_name, :last_name, :role, :mobile_number, :address ])
  end
end
