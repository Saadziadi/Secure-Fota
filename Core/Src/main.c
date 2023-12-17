/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file           : main.c
  * @brief          : Main program body
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2022 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */
/* USER CODE END Header */
/* Includes ------------------------------------------------------------------*/
#include "main.h"

/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sha1.h>
#include <hmac.h>




/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */

/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */
#define MAX_BLOCK_SIZE          ( 1024 )                  //1KB
#define POLYNOMIAL           0x04C11DB7
#define APP_START_ADDRESS    0x08005000U
#define SHA1_HASH_SIZE         20
#define Signature_Size         160
#define HMAC_ADRESS          0x08007500U
/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */
#define MAJOR 0
#define MINOR 1
/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/
 UART_HandleTypeDef huart3;

/* USER CODE BEGIN PV */
uint16_t application_write_idx = 0;
uint32_t crc = 0xFFFFFFFF;
uint16_t i = 0;
uint8_t yy;
uint8_t Nloop = 0;
HAL_StatusTypeDef ret;
uint8_t xx;
uint8_t zz= 0xFF;
uint8_t ResCom = 0xFF ;
uint16_t halfword_data = 0XFF;
uint8_t * HMAC_VALUE = (uint8_t *)(0x08007500U);
uint8_t SHA1outp[20];
uint64_t Real_SIGNATURE[20];
uint64_t public_key, private_key, modulus;
size_t len = 20;
uint8_t decrypted_SIGNATURE[20];
/*             SECURE BOOT V                       */
const uint8_t* secret_key = (const uint8_t*) "saadoune";
const uint32_t firmware_size = 572;
const uint8_t* firmware_data = (const uint8_t*)APP_START_ADDRESS;
uint8_t hmac_result[SHA1_HASH_SIZE];


/*             SECURE FLASHING         */
uint8_t Signature_KBUF[Signature_Size];

/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);
static void MX_GPIO_Init(void);
static void MX_USART3_UART_Init(void);
/* USER CODE BEGIN PFP */
HAL_StatusTypeDef Wait_OTA_Request( void );
static void OTA_Update( void );
uint32_t CRC32(uint8_t* , uint32_t) ;
static void calculate_sha1(const uint8_t* , unsigned , uint8_t* );
void encrypt(uint8_t *, uint8_t , uint8_t );
void decrypt(uint8_t *, uint8_t , uint8_t );
void Receive_Signature(void);
HAL_StatusTypeDef Wait_Signature( void );
void generate_rsa_key_pair(uint64_t *, uint64_t *, uint64_t *);
void rsa_decrypt(uint64_t *, size_t , uint64_t , uint64_t , uint8_t *) ;
void convertByteArrayToUInt64Array (uint8_t* , uint64_t* );
static void goto_application( void );
/* USER CODE END PFP */

/* Private user code ---------------------------------------------------------*/
/* USER CODE BEGIN 0 */

/* USER CODE END 0 */

/**
  * @brief  The application entry point.
  * @retval int
  */
int main(void)
{
  /* USER CODE BEGIN 1 */

  /* USER CODE END 1 */

  /* MCU Configuration--------------------------------------------------------*/

  /* Reset of all peripherals, Initializes the Flash interface and the Systick. */
  HAL_Init();

  /* USER CODE BEGIN Init */

  /* USER CODE END Init */

  /* Configure the system clock */
  SystemClock_Config();

  /* USER CODE BEGIN SysInit */

  /* USER CODE END SysInit */

  /* Initialize all configured peripherals */
  MX_GPIO_Init();
  MX_USART3_UART_Init();
  /* USER CODE BEGIN 2 */
  /* USER CODE END 2 */

  /* Infinite loop */
  /* USER CODE BEGIN WHILE */


   // Calculate the required size for the uint8_t array

   HAL_FLASH_Unlock();
   FLASH_EraseInitTypeDef EraseInitStruct;
   uint32_t SectorError;
   EraseInitStruct.TypeErase     = FLASH_TYPEERASE_PAGES;
   EraseInitStruct.PageAddress   = APP_START_ADDRESS;
   EraseInitStruct.NbPages       = 5;
   generate_rsa_key_pair(&public_key, &private_key, &modulus);

  if (Wait_OTA_Request() == 1)
   {

       HAL_FLASHEx_Erase( &EraseInitStruct, &SectorError );

	   OTA_Update();

	   Nloop = 0 ;
	   Receive_Signature();
	   // Calculate the required size for the uint8_t array



	   convertByteArrayToUInt64Array(Signature_KBUF , Real_SIGNATURE );
	   rsa_decrypt(Real_SIGNATURE, len, public_key, modulus, decrypted_SIGNATURE);      /* decrypt signature and extract HASH1 */

	   calculate_sha1(firmware_data, firmware_size , SHA1outp )  ;  /* calculate HASH2  */

	   uint8_t result = memcmp(decrypted_SIGNATURE, SHA1outp, sizeof(SHA1outp));
	   if (result == 0)
	   {
		printf("FIRMWARE IS AUTHENTICATED \n");
		hmac_sha1(secret_key, 20 , firmware_data, firmware_size, hmac_result);   /*HASH1==HASH2 ---------->   UPDATE HMAC WITHOUT ERASING           */
		HAL_FLASH_Unlock();
		HAL_FLASH_Program( FLASH_TYPEPROGRAM_HALFWORD,
										(HMAC_ADRESS ),
										*hmac_result
									  );                   /*STORE MAC */
		printf("UPDATE THE FIRMWARE MAC \n");
		HAL_FLASH_Lock();
	   }

	   else
	   {
		printf("FIRMWARE IS NOT AUTHENTICATED  \n");
		printf("CANNOT UPDATE THE FIRMWARE \n");
		HAL_FLASH_Unlock();
		FLASH_EraseInitTypeDef EraseInitStruct;
		uint32_t SectorError;
		EraseInitStruct.TypeErase     = FLASH_TYPEERASE_PAGES;
		EraseInitStruct.PageAddress   = APP_START_ADDRESS;
		EraseInitStruct.NbPages       = 15;
		HAL_FLASHEx_Erase( &EraseInitStruct, &SectorError );            /*HASH1!=HASH2---------------> ERASE FIRMWARE */
	   }



   }


   hmac_sha1(secret_key, 20 , firmware_data, firmware_size, hmac_result);         /*calculate MAC using HMAC algorithm and compare it with stored one ,,, if equal jump to target   else   erase */

        if (*hmac_result == *HMAC_VALUE)                                        /*THIS IS THE CASE WHERE THERE IS NO FIRMWARE UPDATE REQUEST , ITS HERE WHEN WE SHOULD APPLY SECURE BOOT */
        {
        	printf("EXECUTE THE APPLICATION \n");
        	goto_application();
        }
        else
        {
        	printf("CANNOT EXECUTE APPLICATION \n");
        	printf("SECURITY ACCESS DENIED \n");
        	HAL_Delay(1500);
        	printf("ECU RESET IS REQUIRED   \n");
        	printf("WAITINF FOR RESET COMMAND \n");

        	while(1)
        	{

            HAL_UART_Receive(&huart3, &ResCom, 1, 500);
            if(ResCom != 0xFF)
              {
            	NVIC_SystemReset();
            	ResCom = 0xFF;
              }

        	}
        }






  while (1)
  {
    /* USER CODE END WHILE */

    /* USER CODE BEGIN 3 */


  }
  /* USER CODE END 3 */
}

/**
  * @brief System Clock Configuration
  * @retval None
  */
void SystemClock_Config(void)
{
  RCC_OscInitTypeDef RCC_OscInitStruct = {0};
  RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};

  /** Initializes the RCC Oscillators according to the specified parameters
  * in the RCC_OscInitTypeDef structure.
  */
  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSI;
  RCC_OscInitStruct.HSIState = RCC_HSI_ON;
  RCC_OscInitStruct.HSICalibrationValue = RCC_HSICALIBRATION_DEFAULT;
  RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;
  RCC_OscInitStruct.PLL.PLLSource = RCC_PLLSOURCE_HSI_DIV2;
  RCC_OscInitStruct.PLL.PLLMUL = RCC_PLL_MUL16;
  if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK)
  {
    Error_Handler();
  }

  /** Initializes the CPU, AHB and APB buses clocks
  */
  RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK|RCC_CLOCKTYPE_SYSCLK
                              |RCC_CLOCKTYPE_PCLK1|RCC_CLOCKTYPE_PCLK2;
  RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
  RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
  RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV2;
  RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV1;

  if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_2) != HAL_OK)
  {
    Error_Handler();
  }
}

/**
  * @brief USART3 Initialization Function
  * @param None
  * @retval None
  */
static void MX_USART3_UART_Init(void)
{

  /* USER CODE BEGIN USART3_Init 0 */

  /* USER CODE END USART3_Init 0 */

  /* USER CODE BEGIN USART3_Init 1 */

  /* USER CODE END USART3_Init 1 */
  huart3.Instance = USART3;
  huart3.Init.BaudRate = 9600;
  huart3.Init.WordLength = UART_WORDLENGTH_8B;
  huart3.Init.StopBits = UART_STOPBITS_1;
  huart3.Init.Parity = UART_PARITY_NONE;
  huart3.Init.Mode = UART_MODE_TX_RX;
  huart3.Init.HwFlowCtl = UART_HWCONTROL_NONE;
  huart3.Init.OverSampling = UART_OVERSAMPLING_16;
  if (HAL_UART_Init(&huart3) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN USART3_Init 2 */

  /* USER CODE END USART3_Init 2 */

}

/**
  * @brief GPIO Initialization Function
  * @param None
  * @retval None
  */
static void MX_GPIO_Init(void)
{
  GPIO_InitTypeDef GPIO_InitStruct = {0};

  /* GPIO Ports Clock Enable */
  __HAL_RCC_GPIOC_CLK_ENABLE();
  __HAL_RCC_GPIOB_CLK_ENABLE();
  __HAL_RCC_GPIOA_CLK_ENABLE();

  /*Configure GPIO pin Output Level */
  HAL_GPIO_WritePin(GPIOC, GPIO_PIN_13|GPIO_PIN_14|GPIO_PIN_15, GPIO_PIN_RESET);

  /*Configure GPIO pin Output Level */
  HAL_GPIO_WritePin(GPIOB, GPIO_PIN_12, GPIO_PIN_RESET);

  /*Configure GPIO pins : PC13 PC14 PC15 */
  GPIO_InitStruct.Pin = GPIO_PIN_13|GPIO_PIN_14|GPIO_PIN_15;
  GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  HAL_GPIO_Init(GPIOC, &GPIO_InitStruct);

  /*Configure GPIO pin : PB12 */
  GPIO_InitStruct.Pin = GPIO_PIN_12;
  GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  HAL_GPIO_Init(GPIOB, &GPIO_InitStruct);

}

/* USER CODE BEGIN 4 */


static void OTA_Update(void)
{
    yy = 0xFF;
    xx = 0XFF;
    Nloop = 0 ;
    printf("PREPARING FOR FIRMWARE UPDATE \n");
    HAL_Delay(8000);
    printf("READY TO UPDATE THE FIRMWARE  \n");
    printf("SEND YOUR APPLICATION \n");

    HAL_GPIO_WritePin(GPIOC, GPIO_PIN_14 , 1);
    while(1)
    {


      HAL_UART_Receive(&huart3, &yy, 1, 5000);

      HAL_UART_Receive(&huart3, &xx, 1, 5000);

      if((xx == 0xFF) && (yy == 0xFF))
       {
    	  Nloop ++ ;
       }


        halfword_data = yy | (xx << 8 );



     ret = HAL_FLASH_Program( FLASH_TYPEPROGRAM_HALFWORD,
                                (APP_START_ADDRESS + application_write_idx ),
                                halfword_data
                              );


      yy = 0xFF;
      xx = 0XFF;

      if( ret == HAL_OK )
      {
         //update the data count
         application_write_idx += 2;
      }
      else
       {

         break;
       }
      if(Nloop == 1)
      {

    	  HAL_GPIO_WritePin(GPIOC, GPIO_PIN_14 , 0);
    	  Nloop = 0 ;


    	  break;
      }

    }
	  ret = HAL_FLASH_Lock();
}


static void goto_application( void )
{
	void (*app_reset_handler1)(void) = (void*)(*((volatile uint32_t*)( APP_START_ADDRESS+ 4U)));
	  __set_MSP(*(volatile uint32_t*) APP_START_ADDRESS );
	  HAL_GPIO_WritePin(GPIOC, GPIO_PIN_13, GPIO_PIN_RESET );
	 	app_reset_handler1();
}


HAL_StatusTypeDef Wait_OTA_Request( void )
{
 zz = 0xFF ;
 printf("WAITING FOR OTA DEMAND \n");
  while(1)
  {
    //Toggle GPIO
    HAL_GPIO_TogglePin(GPIOC, GPIO_PIN_13);

    HAL_UART_Receive(&huart3, &zz, 1, 500);
    if (zz == 0xFF)
     {

     }
    else
     {

     ret = 1 ;
	 break ;
     }

    if( Nloop == 20 )
     {
      ret = 0 ;
      Nloop = 0;
      break;
     }
    Nloop++;

  }
  if(zz == 0xFF) {
	  printf("NO OTA DEMAND  \n");
	  printf("CHECK OLD APPLICATION \n");
  }

  return ret;
}


uint32_t CRC32(uint8_t* data, uint32_t length)
{

    for (uint32_t i = 0; i < length; i++)
     {
        crc ^= data[i];

        for (uint32_t j = 0; j < 8; j++)
         {
            if (crc & 0x80000000)
             {
                crc = (crc << 1) ^ POLYNOMIAL;
             }
            else
             {
                crc <<= 1;
             }
         }
     }

    return crc;
}



static void calculate_sha1(const uint8_t* msg, unsigned nbytes, uint8_t* output)
{
  struct sha1 ctx;

  sha1_reset(&ctx);
  sha1_input(&ctx, msg, nbytes);
  sha1_result(&ctx, output);
}



HAL_StatusTypeDef Wait_Signature( void )
{
  zz = 0xFF;
  printf("WAITING FOR SIGNATURE \n");

  while(1)
  {
    //Toggle GPIO
    HAL_GPIO_TogglePin(GPIOB, GPIO_PIN_12);
    HAL_UART_Receive(&huart3, &zz, 1, 100);
    if (zz == 0xFF)
     {

     }
    else
     {

      ret = 1 ;
      break ;
     }

    if( Nloop == 100 )
     {
      ret = 0 ;
      Nloop = 0;
      break;
     }
    Nloop++;

  }
  HAL_GPIO_WritePin(GPIOB, GPIO_PIN_12 , 0);
  return ret;
}


void Receive_Signature (void)
{
	yy = 0xFF ;
	xx = 0xFF ;
	i = 0 ;
    printf("PREPARE YOUR FIRMWARE SIGNATURE \n");
    HAL_Delay(6000);
    printf("READY TO RECEIVE THE SIGNATURE \n");
	 HAL_GPIO_WritePin(GPIOC, GPIO_PIN_15 , 1);
	while(1)
	{

	    HAL_UART_Receive(&huart3, &yy, 1, 5000);


	    HAL_UART_Receive(&huart3, &xx, 1, 5000);

	    if((xx == 0xFF) && (yy == 0xFF))
	      {
	   	  Nloop ++ ;
	      }

		    Signature_KBUF[i++]   = yy ;
		    Signature_KBUF[i++] = xx ;




		yy = 0xFF ;
		xx = 0xFF ;
	    if(Nloop == 1)
	      {

	    	  Nloop = 0 ;

	    	  break;
	      }
	}
	i =0 ;
	 HAL_GPIO_WritePin(GPIOC, GPIO_PIN_15 , 0);
	 if(Signature_KBUF[0] == 0 && Signature_KBUF[1]==0)
	 {
	   printf("NO SIGNATURE RECEIVED \n");
	 }

	 else printf("SIGNATURE RECEIVED SUCCESFULLY \n");

}

uint64_t mod_exp(uint64_t base, uint64_t exponent, uint64_t modulus) {
    uint64_t result = 1;

    while (exponent > 0) {
        if (exponent % 2 == 1) {
            result = (result * base) % modulus;
        }
        base = (base * base) % modulus;
        exponent /= 2;
    }

    return result;
}

// Function to calculate the greatest common divisor (GCD) of two numbers
uint64_t gcd(uint64_t a, uint64_t b) {
    if (b == 0) {
        return a;
    }
    return gcd(b, a % b);
}

// Function to calculate the modular multiplicative inverse (a^(-1) mod m)
uint64_t mod_inverse(uint64_t a, uint64_t m) {
    for (uint64_t x = 1; x < m; x++) {
        if ((a * x) % m == 1) {
            return x;
        }
    }
    return 0; // Inverse does not exist
}

// Function to generate RSA key pair
void generate_rsa_key_pair(uint64_t *public_key, uint64_t *private_key, uint64_t *modulus) {
    // Choose two large prime numbers (for simplicity, these are hardcoded here)
    uint64_t p = 23;
    uint64_t q = 29;

    *modulus = p * q;
    uint64_t phi = (p - 1) * (q - 1);

    // Choose public exponent (for simplicity, this is hardcoded here)
    *public_key = 17;

    // Calculate private exponent
    *private_key = mod_inverse(*public_key, phi);
}

// Function to encrypt a message using RSA
void rsa_encrypt(uint8_t *plaintext, size_t len, uint64_t public_key, uint64_t modulus, uint64_t *ciphertext) {
    for (size_t i = 0; i < len; i++) {
        ciphertext[i] = mod_exp(plaintext[i], public_key, modulus);
    }
}

// Function to decrypt a message using RSA
void rsa_decrypt(uint64_t *ciphertext, size_t len, uint64_t private_key, uint64_t modulus, uint8_t *plaintext) {
    for (size_t i = 0; i < len; i++) {
        plaintext[i] = mod_exp(ciphertext[i], private_key, modulus);
    }
}


void convertByteArrayToUInt64Array( uint8_t* byteArray, uint64_t* uint64Array) {
    // Copy 8 bytes from the byte array to each uint64_t element
    for (size_t i = 0; i < 20; i++) {
        memcpy(&uint64Array[i], &byteArray[i * 8], 8);
    }
}

#ifdef __GNUC__
  /* With GCC, small printf (option LD Linker->Libraries->Small printf
     set to 'Yes') calls __io_putchar() */
int __io_putchar(int ch)
#else
int fputc(int ch, FILE *f)
#endif /* __GNUC__ */
{
  /* Place your implementation of fputc here */
  /* e.g. write a character to the UART3 and Loop until the end of transmission */
  HAL_UART_Transmit(&huart3, (uint8_t *)&ch, 1, HAL_MAX_DELAY);
  return ch;
}

/* USER CODE END 4 */

/**
  * @brief  This function is executed in case of error occurrence.
  * @retval None
  */
void Error_Handler(void)
{
  /* USER CODE BEGIN Error_Handler_Debug */
  /* User can add his own implementation to report the HAL error return state */
  __disable_irq();
  while (1)
  {
  }
  /* USER CODE END Error_Handler_Debug */
}

#ifdef  USE_FULL_ASSERT
/**
  * @brief  Reports the name of the source file and the source line number
  *         where the assert_param error has occurred.
  * @param  file: pointer to the source file name
  * @param  line: assert_param error line source number
  * @retval None
  */
void assert_failed(uint8_t *file, uint32_t line)
{
  /* USER CODE BEGIN 6 */
  /* User can add his own implementation to report the file name and line number,
     ex: printf("Wrong parameters value: file %s on line %d\r\n", file, line) */
  /* USER CODE END 6 */
}
#endif /* USE_FULL_ASSERT */
