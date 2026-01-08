export interface Product {
  id: string;
  name: string;
  price: number;
  description: string | null;
  imageUrl: string;
}

export interface User {
  id: string;
  email: string;
  role: string;
}

export interface Review {
  id: string;
  content: string;
  author: string;
  createdAt: string;
}

export interface CartItem {
  id: string;
  productId: string;
  quantity: number;
  product: {
    id: string;
    name: string;
    price: number;
    imageUrl: string;
  };
}

export interface CartData {
  cartItems: CartItem[];
  total: number;
}

export interface DeliveryAddress {
  street: string;
  city: string;
  state: string;
  zipCode: string;
  country: string;
}

export interface UserData {
  email: string;
  address: DeliveryAddress | null;
}

export interface Order {
  id: string;
  total: number;
  status: string;
  customerName?: string;
  customerEmail?: string;
  deliveryAddress?: DeliveryAddress;
  flag?: string;
}

export interface Flag {
  id: string;
  flag: string;
  slug: string;
  cve?: string | null;
  markdownFile: string;
}

export interface ProductCardProps {
  id: string;
  name: string;
  price: number;
  imageUrl: string;
}

export interface ProductGridProps {
  products: Product[];
  title?: string;
  subtitle?: string;
}

export interface ProductDetailClientProps {
  product: Product;
}

export interface AdminOrder {
  id: string;
  userId: string;
  total: number;
  status: string;
  user: {
    email: string;
  };
  address: DeliveryAddress;
}

export interface AdminResponse {
  message: string;
  flag?: string;
  user?: User;
}

export interface OrderSearchResult extends Omit<Order, "deliveryAddress"> {
  street: string;
  city: string;
  state: string;
  zipCode: string;
  country: string;
}
