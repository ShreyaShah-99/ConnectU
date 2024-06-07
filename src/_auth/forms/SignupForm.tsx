import * as z from 'zod';
import { zodResolver } from '@hookform/resolvers/zod';
import { Button } from '@/components/ui/button';
import { useForm } from 'react-hook-form';
import { Link } from 'react-router-dom';
import {
  Form,
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from '@/components/ui/form';
import { Input } from '@/components/ui/input';
import { SignupValidation } from '@/lib/validation';
import Loader from '@/components/ui/shared/Loader';
import { createUserAccount } from '@/lib/appwrite/api';

// const formSchema = z.object({
//   username: z.string().min(2).max(50),
// });

const SignupForm = () => {
  const isLoading = false;

  // 1. Define your form.
  const form = useForm<z.infer<typeof SignupValidation>>({
    resolver: zodResolver(SignupValidation),
    defaultValues: {
      "name": '',
      "username": '',
      "email": '',
      "password": '',
    },
  });

  // 2. Define a submit handler.
  async function onSubmit(values: z.infer<typeof SignupValidation>) {
    //create the user
    const newUser = await createUserAccount(values);
    console.log('newuser',newUser)
  }

  const Fieldnames = ['name', 'username', 'email', 'password'];

  return (
    <>
      <Form {...form}>
        <div className="sm:w-420 flex-center flex-col">
          <img src="/assets/images/logo.svg" />
          <h2 className="h3-bold md:h2-bold pt-5 sm:pt-12">
            Create a new account
          </h2>
          <p className="text-light-3 small-medium md:base-regular mt-2">
            To use ConnectU please enter your account details
          </p>

          <form
            onSubmit={form.handleSubmit(onSubmit)}
            className="flex flex-col gap-5 w-full mt-4"
          >
            {Fieldnames?.map((item, index) => (
              <FormField
                control={form.control}
                name={item}
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>{item}</FormLabel>
                    <FormControl>
                      <Input
                        placeholder={item}
                        type={
                          item == 'email'
                            ? 'email'
                            : item == 'password'
                            ? 'password'
                            : 'text'
                        }
                        className="shad-input"
                        {...field}
                      />
                    </FormControl>
                    <FormDescription>
                      This is your public display name.
                    </FormDescription>
                    <FormMessage />
                  </FormItem>
                )}
              />
            ))}
            <Button type="submit" className="shad-button_primary">
              {isLoading ? (
                <div className="flex-center gap-2">
                  <Loader /> Loading...
                </div>
              ) : (
                'Sign Up'
              )}
            </Button>
            <p className="text-small-regular text-light-2 text-center mt-2">
              Already have an Account?
              <Link to="/sign-in" className="text-primary-500 text-small=semibold ml-1">Log in</Link>
            </p>
          </form>
        </div>
      </Form>
    </>
  );
};

export default SignupForm;
