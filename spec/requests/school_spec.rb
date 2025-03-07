require 'rails_helper'

RSpec.describe Api::SchoolsController, type: :controller do
  let!(:school) { create(:school) }
  let(:valid_attributes) { attributes_for(:school) }
  let(:invalid_attributes) { { name: "", city: "", state: "" } }

  describe "GET #index" do
    it "returns all schools" do
      get :index
      expect(response).to have_http_status(:ok)
      expect(JSON.parse(response.body).size).to eq(1)
    end
  end

  describe "GET #show" do
    it "returns a valid school" do
      get :show, params: { id: school.id }
      expect(response).to have_http_status(:ok)
      expect(JSON.parse(response.body)["id"]).to eq(school.id)
    end
  end

  describe "POST #create" do
    it "creates a new school with valid attributes" do
      expect {
        post :create, params: { school: valid_attributes }
      }.to change(School, :count).by(1)

      expect(response).to have_http_status(:created)
    end

    it "fails to create a school with invalid attributes" do
      post :create, params: { school: invalid_attributes }
      expect(response).to have_http_status(:unprocessable_entity)
      expect(JSON.parse(response.body)["errors"]).to include("Name can't be blank", "City can't be blank", "State can't be blank")
    end
  end

  describe "PATCH #update" do
    it "updates a school successfully" do
      patch :update, params: { id: school.id, school: { name: "Updated School" } }
      expect(response).to have_http_status(:ok)
      expect(school.reload.name).to eq("Updated School")
    end

    it "fails to update a school with invalid data" do
      patch :update, params: { id: school.id, school: invalid_attributes }
      expect(response).to have_http_status(:unprocessable_entity)
      expect(JSON.parse(response.body)["errors"]).to include("Name can't be blank")
    end
  end

  describe "DELETE #destroy" do
    it "deletes a school" do
      expect {
        delete :destroy, params: { id: school.id }
      }.to change(School, :count).by(-1)

      expect(response).to have_http_status(:ok)
    end

    it "returns 404 if school not found" do
      delete :destroy, params: { id: 9999 }
      expect(response).to have_http_status(:not_found)
    end
  end
end
