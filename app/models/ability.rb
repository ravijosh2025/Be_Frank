# frozen_string_literal: true

class Ability
  include CanCan::Ability

  def initialize(user)
    user ||= User.new # Guest user (not logged in)

    if user.admin?
      can :manage, Event # Admin can perform all CRUD operations
      can :manage, User
      can :manage, School
      can :manage, Donation
      can :manage, Feedback
    else
      can :read, Event  # Regular users can only read events
      can :create, User
      can :manage, Donation
      can :manage, Feedback
      cannot [ :create, :update, :destroy ], Event # Explicitly deny non-admins from modifying events
      cannot [ :index, :update, :destroy ], User
      cannot [ :index, :create, :update, :destroy ], School
      # cannot [ :index ], Donation
    end
  end
end
