require 'rails_helper'

RSpec.describe Api::UsersController, type: :controller do
  let(:user) { create(:user) }
  let(:admin) { create(:user, role: 'admin') }
  let(:valid_attributes) { attributes_for(:user) }
  let(:invalid_attributes) { { first_name: "", email: "invalid" } }

  describe "GET #index" do
    it "returns all users" do
      user1 = create(:user)
      user2 = create(:user)

      get :index
      expect(response).to have_http_status(:ok)
      expect(JSON.parse(response.body).size).to eq(3)
    end
  end

  describe "GET #show" do
    it "returns a valid user" do
      get :show, params: { id: user.id }
      expect(response).to have_http_status(:ok)
      expect(JSON.parse(response.body)["id"]).to eq(user.id)
    end

    it "returns not found for an invalid user" do
      get :show, params: { id: 9999 }
      expect(response).to have_http_status(:not_found)
    end
  end

  describe "POST #create" do
    it "creates a new user with valid attributes" do
      expect {
        post :create, params: { user: valid_attributes }
      }.to change(User, :count).by(1)

      expect(response).to have_http_status(:created)
    end

    it "fails to create a user with invalid attributes" do
      post :create, params: { user: invalid_attributes }
      expect(response).to have_http_status(:unprocessable_entity)
      expect(JSON.parse(response.body)["errors"]).to include("First name can't be blank")
    end
  end

  describe "PATCH #update" do
    it "updates a user successfully" do
      patch :update, params: { id: user.id, user: { first_name: "Updated" } }
      expect(response).to have_http_status(:ok)
      expect(user.reload.first_name).to eq("Updated")
    end

    it "fails to update a user with invalid data" do
      patch :update, params: { id: user.id, user: { email: "invalid" } }
      expect(response).to have_http_status(:unprocessable_entity)
      expect(JSON.parse(response.body)["errors"]).to include("Email is invalid")
    end
  end

  describe "DELETE #destroy" do
    it "deletes a user" do
      delete :destroy, params: { id: user.id }
      expect(response).to have_http_status(:ok)
      expect(User.exists?(user.id)).to be_falsey
    end
  end
end
