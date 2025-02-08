class User < ApplicationRecord
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable, :trackable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :validatable

         validates :first_name, presence: true
         validates :last_name, presence: true
         validates :role, presence:true
         validates :email, format: { with: Devise.email_regexp }, presence: true, uniqueness: { case_insensitive: true }
         validates :mobile_number, presence: true, format: { with: /\A(\+\d{1,3}[- ]?)?\d{10}\z/, message: "must be a valid phone number" }
         validates :address, presence:true
end



