Rails.application.routes.draw do
  root 'home#index'
  post 'redirect', to: 'home#redirect'
end
