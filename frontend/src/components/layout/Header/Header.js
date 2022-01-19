import React from 'react';
import { ReactNavbar } from 'overlay-navbar';
import logo from "../../../images/logo.png";

const options = {
    burgerColorHover: "#eb4034",
    logo,
    logoWidth: "12vmax",
    navColor1: "white",
    logoHoverSize: "20px",
    logoHoverColor: "#1A3E6D",
    link1Text: "Home",
    link2Text: "Products",
    link3Text: "Contact",
    link4Text: "About",
    link1Url: "/",
    link2Url: "/products",
    link3Url: "/contact",
    link4Url: "/about",
    link1Size: "1.3vmax",
    link1Color: "rgba(35, 35, 35,0.8)",
    nav1justifyContent: "flex-start",
    nav2justifyContent: "flex-end",
    nav3justifyContent: "flex-start",
    nav4justifyContent: "flex-start",
    link1ColorHover: "#E47D25",
    link1Margin: "1vmax",
    profileIconUrl: "/login",
    profileIconColor: "rgba(35, 35, 35,0.8)",
    searchIconColor: "rgba(35, 35, 35,0.8)",
    cartIconColor: "rgba(35, 35, 35,0.8)",
    profileIconColorHover: "#E47D25",
    searchIconColorHover: "#E47D25",
    cartIconColorHover: "#E47D25",
    cartIconMargin: "1vmax",
  };
  
  const Header = () => {
    return <ReactNavbar {...options} />;
  };
  
  export default Header;
