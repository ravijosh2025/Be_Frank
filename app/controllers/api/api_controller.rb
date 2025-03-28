module Api
  class ApiController < ActionController::API
    include Auth
    include CanCan::ControllerAdditions
    load_and_authorize_resource

    rescue_from CanCan::AccessDenied, with: :handle_access_denied
    rescue_from ActiveRecord::RecordNotFound, with: :handle_record_not_found
    rescue_from ActiveRecord::RecordInvalid, with: :handle_record_invalid
    rescue_from ActionController::ParameterMissing, with: :handle_parameter_missing
    rescue_from StandardError, with: :handle_internal_server_error

    private

    # Handle unauthorized access
    def handle_access_denied(exception)
      render json: { error: "You are not authorized to perform this action" }, status: :forbidden
    end

    # Handle record not found (e.g., when querying a missing record)
    def handle_record_not_found(exception)
      render json: { error: "Record not found", details: exception.message }, status: :not_found
    end

    # Handle validation errors from ActiveRecord
    def handle_record_invalid(exception)
      render json: { error: "Validation failed", details: exception.record.errors.full_messages }, status: :unprocessable_entity
    end

    # Handle missing required parameters
    def handle_parameter_missing(exception)
      render json: { error: "Required parameter missing", details: exception.message }, status: :bad_request
    end

    # Catch all other unhandled exceptions
    def handle_internal_server_error(exception)
      render json: { error: "Internal server error", details: exception.message }, status: :internal_server_error
    end
  end
end
