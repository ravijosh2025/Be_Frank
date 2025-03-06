Rails.application.config.middleware.insert_before 0, Rack::Cors do
  allow do
    origins "*"  # Change '*' to your frontend domain for security

    resource "*",
      headers: :any,
      expose: [ "Authorization" ], # If using JWT or custom headers
      methods: [ :get, :post, :put, :patch, :delete, :options, :head ]
  end
end
